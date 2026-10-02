package apiserver

import (
	"bytes"
	"encoding/json"
)

// SecurityAgentActionArguments is deliberately not a map: only these typed,
// validated fields may cross the private plan-to-display boundary.
type SecurityAgentActionArguments struct {
	TargetID        string `json:"target_id"`
	ExpectedVersion int64  `json:"expected_version,omitempty"`
	TargetStatus    string `json:"target_status,omitempty"`
	Mode            string `json:"mode,omitempty"`
	Scope           string `json:"scope,omitempty"`
	TTLSeconds      int    `json:"ttl_seconds,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	IntegrationID   string `json:"integration_id,omitempty"`
}

func decodeSecurityAgentActionArguments(action string, raw json.RawMessage) (*SecurityAgentActionArguments, error) {
	var fields []string
	switch action {
	case "run_test", "rerun_test":
		fields = []string{"target_id", "expected_version"}
	case "update_finding_response":
		fields = []string{"target_id", "expected_version", "target_status"}
	case "create_temporary_policy":
		fields = []string{"target_id", "mode", "scope", "ttl_seconds"}
	case "isolate_session":
		fields = []string{"target_id", "session_id", "device_id", "scope", "ttl_seconds"}
	case "revoke_integration_connection":
		fields = []string{"target_id", "integration_id"}
	default:
		return nil, ErrRepositoryUnavailable
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if stringIn(action, "run_test", "rerun_test") {
			return nil, ErrRepositoryUnavailable
		}
		return nil, nil
	}
	var value SecurityAgentActionArguments
	if stringIn(action, "run_test", "rerun_test") {
		if _, err := auditExportClosedObject(raw, 1024, fields...); err != nil {
			return nil, ErrRepositoryUnavailable
		}
	}
	if !exactJSONFields(raw, fields...) || decodeStrictDiscovery(raw, &value) != nil || !validProductID(value.TargetID) {
		return nil, ErrRepositoryUnavailable
	}
	valid := false
	switch action {
	case "run_test", "rerun_test":
		valid = value.ExpectedVersion >= 1 && value.ExpectedVersion <= 1000000
	case "update_finding_response":
		valid = value.ExpectedVersion >= 1 && value.ExpectedVersion <= 9007199254740991 && value.TargetStatus == "under_review"
	case "create_temporary_policy":
		valid = value.Mode == "block" && value.Scope == value.TargetID && value.TTLSeconds >= 60 && value.TTLSeconds <= 3600
	case "isolate_session":
		valid = value.SessionID == value.TargetID && validProductID(value.DeviceID) && validProductID(value.Scope) && value.TTLSeconds >= 60 && value.TTLSeconds <= 3600
	case "revoke_integration_connection":
		valid = validProductID(value.IntegrationID)
	}
	if !valid {
		return nil, ErrRepositoryUnavailable
	}
	return &value, nil
}
