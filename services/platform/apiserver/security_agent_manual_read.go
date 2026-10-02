package apiserver

import "encoding/json"

func securityAgentManualReadFields(raw []byte, required []string, optional ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return false
	}
	fields := append([]string(nil), required...)
	for _, key := range optional {
		if _, ok := object[key]; ok {
			fields = append(fields, key)
		}
	}
	if manual, ok := object["manual_trigger"]; ok {
		var value SecurityAgentManualTrigger
		if json.Unmarshal(manual, &value) != nil {
			return false
		}
		fields = append(fields, "manual_trigger")
	}
	_, err := auditExportClosedObject(raw, 131072, fields...)
	return err == nil
}

func (value *SecurityAgentRun) UnmarshalJSON(raw []byte) error {
	if !securityAgentManualReadFields(raw, []string{"id", "agent_id", "state", "evidence_ids", "definition_version", "version"}) {
		return ErrRepositoryUnavailable
	}
	type plain SecurityAgentRun
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return ErrRepositoryUnavailable
	}
	*value = SecurityAgentRun(decoded)
	return nil
}

func (value *SecurityAgentApproval) UnmarshalJSON(raw []byte) error {
	if !securityAgentManualReadFields(raw, []string{"id", "run_id", "step_id", "state", "expires_at", "version", "expected_effect", "reversible", "ttl_seconds", "evidence_summary"}, "attack_lab", "approval_context") {
		return ErrRepositoryUnavailable
	}
	type plain SecurityAgentApproval
	var decoded plain
	if err := decodeStrictDiscovery(raw, &decoded); err != nil {
		return ErrRepositoryUnavailable
	}
	*value = SecurityAgentApproval(decoded)
	return nil
}

func validSecurityAgentManualEvidence(manual *SecurityAgentManualTrigger, evidence []string, maximum int) bool {
	if manual != nil {
		return validSecurityAgentManualTrigger(manual) && evidence != nil && len(evidence) == 0
	}
	return len(evidence) >= 1 && len(evidence) <= maximum && validUniqueProductIDs(evidence)
}

func sameSecurityAgentManualTrigger(left, right *SecurityAgentManualTrigger) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validSecurityAgentManualRunContext(detail SecurityAgentRunDetail) bool {
	manual := detail.Run.ManualTrigger
	if manual != nil && detail.EvidenceIDs == nil {
		return false
	}
	if detail.RunContext == nil {
		return true
	} // Older reads omit negotiated context.
	trigger := detail.RunContext.Trigger
	if manual == nil {
		return trigger == nil || trigger.Kind != "manual"
	}
	return trigger != nil && trigger.Kind == "manual" && "sha256:"+trigger.ID == manual.IntentDigest && trigger.Version == manual.Version
}
