package main

func validSecurityAgentPlannerManualProvenance(value securityAgentPlannerContext) bool {
	manual := value.ManualTrigger
	if manual != nil && (manual.Kind != "manual" || !providerAckPattern.MatchString(manual.IntentDigest) || manual.Version < 1 || manual.Version > 9007199254740991) {
		return false
	}
	count := 0
	for _, evidence := range value.Evidence {
		if evidence.Kind != "manual" {
			continue
		}
		if manual == nil || manual.IntentDigest != "sha256:"+evidence.ID || manual.Version != evidence.Version {
			return false
		}
		count++
	}
	return manual == nil && count == 0 || manual != nil && count == 1
}
