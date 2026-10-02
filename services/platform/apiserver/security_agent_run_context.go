package apiserver

// SecurityAgentRunContext contains only the validated public projection. Raw
// planner receipt text must be sanitized before constructing this value.
type SecurityAgentRunContext struct {
	PreflightStopReason string                   `json:"preflight_stop_reason,omitempty"`
	Trigger             *SecurityAgentRunTrigger `json:"trigger"`
	Rationale           *SecurityAgentRationale  `json:"rationale"`
}

type SecurityAgentRunTrigger struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

type SecurityAgentRationale struct {
	State   string `json:"state"`
	Summary string `json:"summary"`
}

func validSecurityAgentRunContext(value *SecurityAgentRunContext) bool {
	if value == nil {
		return true
	}
	if value.PreflightStopReason != "" && value.PreflightStopReason != "attack_lab_preflight_unavailable" {
		return false
	}
	if value.Trigger != nil && (!stringIn(value.Trigger.Kind, "finding", "attack_path", "runtime_decision", "manual") || !validSecurityAgentRunTriggerID(value.Trigger) || value.Trigger.Version < 1 || value.Trigger.Version > 9007199254740991) {
		return false
	}
	if value.Rationale == nil {
		return true
	}
	if value.Trigger == nil {
		return false
	}
	switch value.Rationale.State {
	case "withheld":
		return value.Rationale.Summary == ""
	case "available":
		text, ok := sanitizeSecurityAgentRationale(value.Rationale.Summary)
		return ok && text == value.Rationale.Summary
	default:
		return false
	}
}

func validSecurityAgentRunTriggerID(trigger *SecurityAgentRunTrigger) bool {
	if trigger.Kind == "manual" {
		return securityAgentPlanHashPattern.MatchString("sha256:" + trigger.ID)
	}
	return validProductID(trigger.ID)
}
