package apiserver

import (
	"bytes"
	"encoding/json"
	"strings"
)

// SecurityAgentActionArguments is deliberately not a map: only these typed,
// validated fields may cross the private plan-to-display boundary.
type SecurityAgentActionArguments struct {
	EvidenceIDs     []SecurityAgentExportSelection `json:"evidence_ids,omitempty"`
	TargetID        string                         `json:"target_id"`
	ExpectedVersion int64                          `json:"expected_version,omitempty"`
	TargetStatus    string                         `json:"target_status,omitempty"`
	AssigneeID      string                         `json:"assignee_id,omitempty"`
	ResponseStatus  string                         `json:"response_status,omitempty"`
	Note            string                         `json:"note,omitempty"`
	Mode            string                         `json:"mode,omitempty"`
	Scope           string                         `json:"scope,omitempty"`
	TTLSeconds      int                            `json:"ttl_seconds,omitempty"`
	SessionID       string                         `json:"session_id,omitempty"`
	DeviceID        string                         `json:"device_id,omitempty"`
	IntegrationID   string                         `json:"integration_id,omitempty"`
}

func decodeSecurityAgentActionArguments(action string, raw json.RawMessage) (*SecurityAgentActionArguments, error) {
	var fields []string
	findingMetadata := false
	switch action {
	case "create_evidence_export":
		fields = []string{"target_id", "evidence_ids"}
	case "run_test", "rerun_test", "start_attack_lab":
		fields = []string{"target_id", "expected_version"}
	case "update_finding_response":
		fields = []string{"target_id", "expected_version", "target_status"}
		var keys map[string]json.RawMessage
		if json.Unmarshal(raw, &keys) != nil {
			return nil, ErrRepositoryUnavailable
		}
		for _, key := range []string{"assignee_id", "response_status", "note"} {
			_, present := keys[key]
			findingMetadata = findingMetadata || present
		}
		if findingMetadata {
			fields = append(fields, "assignee_id", "response_status", "note")
		}
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
		if stringIn(action, "run_test", "rerun_test", "start_attack_lab", "create_evidence_export") {
			return nil, ErrRepositoryUnavailable
		}
		return nil, nil
	}
	var value SecurityAgentActionArguments
	if action == "create_evidence_export" {
		closed, err := auditExportClosedObject(raw, 65536, fields...)
		if err != nil {
			return nil, ErrRepositoryUnavailable
		}
		var selection []json.RawMessage
		if json.Unmarshal(closed["evidence_ids"], &selection) != nil {
			return nil, ErrRepositoryUnavailable
		}
		for _, item := range selection {
			if _, err := auditExportClosedObject(item, 4096, "source_kind", "source_id", "source_version", "association_digest"); err != nil {
				return nil, ErrRepositoryUnavailable
			}
		}
	}
	if stringIn(action, "run_test", "rerun_test", "start_attack_lab", "update_finding_response") {
		if _, err := auditExportClosedObject(raw, 4096, fields...); err != nil {
			return nil, ErrRepositoryUnavailable
		}
	}
	if !exactJSONFields(raw, fields...) || decodeStrictDiscovery(raw, &value) != nil || !validProductID(value.TargetID) {
		return nil, ErrRepositoryUnavailable
	}
	valid := false
	switch action {
	case "create_evidence_export":
		valid = validAgentExportDownloadBinding(SecurityAgentExportBinding{RunID: value.TargetID, StepID: value.TargetID, Selection: value.EvidenceIDs})
	case "run_test", "rerun_test", "start_attack_lab":
		valid = value.ExpectedVersion >= 1 && value.ExpectedVersion <= 1000000
	case "update_finding_response":
		valid = value.ExpectedVersion >= 1 && value.ExpectedVersion <= 9007199254740991 && value.TargetStatus == "under_review"
		if findingMetadata {
			valid = value.ExpectedVersion >= 1 && value.ExpectedVersion <= 9007199254740991 && validProductID(value.AssigneeID) &&
				(value.ResponseStatus == "investigating" && value.TargetStatus == "under_review" || value.ResponseStatus == "open" && value.TargetStatus == "open") &&
				validFindingResponseNote(value.Note)
		}
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

// The fixed White_Space union FEFF boundary set matches SQL and the public
// schema. Compare only: never normalize text an operator approved.
func validFindingResponseNote(note string) bool {
	const edges = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
	return len(note) >= 1 && len(note) <= 512 && strings.Trim(note, edges) == note && strings.IndexFunc(note, func(r rune) bool { return r <= 0x1f || r >= 0x7f && r <= 0x9f }) < 0
}
