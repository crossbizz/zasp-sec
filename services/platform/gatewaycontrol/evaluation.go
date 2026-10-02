package gatewaycontrol

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
)

// EvaluationEvidence records the resolved policy contributors, separately from
// request classification and the transport's action kind. Missing risk is unknown.
type EvaluationEvidence struct {
	Version               int      `json:"version"`
	Action                string   `json:"action"`
	AgentID               string   `json:"agent_id"`
	SessionID             string   `json:"session_id"`
	ContributingPolicyIDs []string `json:"contributing_policy_ids"`
	Risk                  string   `json:"risk,omitempty"`
}

// A pointer field otherwise treats explicit null as omission, and encoding/json
// accepts duplicate outer keys. Neither may erase signed evaluation evidence.
func (value *DecisionEvent) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errHTTPControl
	}
	seenEvaluation := false
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return errHTTPControl
		}
		var field json.RawMessage
		if decoder.Decode(&field) != nil {
			return errHTTPControl
		}
		if strings.EqualFold(name, "evaluation") {
			if name != "evaluation" || seenEvaluation || bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
				return errHTTPControl
			}
			seenEvaluation = true
		}
	}
	if _, err := decoder.Token(); err != nil {
		return errHTTPControl
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errHTTPControl
	}
	type plain DecisionEvent
	var decoded plain
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if strict.Decode(&decoded) != nil {
		return errHTTPControl
	}
	*value = DecisionEvent(decoded)
	return nil
}

func (value *EvaluationEvidence) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errHTTPControl
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return errHTTPControl
		}
		switch name {
		case "version", "action", "agent_id", "session_id", "contributing_policy_ids", "risk":
		default:
			return errHTTPControl
		}
		if _, exists := fields[name]; exists {
			return errHTTPControl
		}
		var field json.RawMessage
		if decoder.Decode(&field) != nil || bytes.Equal(field, []byte("null")) {
			return errHTTPControl
		}
		fields[name] = field
	}
	if _, err := decoder.Token(); err != nil {
		return errHTTPControl
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errHTTPControl
	}
	for _, name := range []string{"version", "action", "agent_id", "session_id", "contributing_policy_ids"} {
		if _, exists := fields[name]; !exists {
			return errHTTPControl
		}
	}
	type plain EvaluationEvidence
	var decoded plain
	if json.Unmarshal(raw, &decoded) != nil {
		return errHTTPControl
	}
	if _, present := fields["risk"]; present && !knownEvaluationRisk(decoded.Risk) {
		return errHTTPControl
	}
	*value = EvaluationEvidence(decoded)
	return nil
}

// ValidEvaluationEvidence is shared by authenticated ingestion and the gateway's
// durable codec. It validates attribution shape, not a substitute policy evaluation.
func ValidEvaluationEvidence(value *EvaluationEvidence, decision string, matched []string) bool {
	if value == nil {
		return true
	}
	if value.Version != 1 || value.Action == "" || len(value.Action) > 64 || strings.TrimSpace(value.Action) != value.Action || strings.ContainsAny(value.Action, "\x00\r\n") || !validProductID(value.AgentID) || !validProductID(value.SessionID) || !validPolicyIDs(value.ContributingPolicyIDs) || value.Risk != "" && !knownEvaluationRisk(value.Risk) {
		return false
	}
	if decision == "allow" && len(value.ContributingPolicyIDs) > 0 || len(value.ContributingPolicyIDs) == 0 && value.Risk != "" {
		return false
	}
	for _, id := range value.ContributingPolicyIDs {
		if !slices.Contains(matched, id) {
			return false
		}
	}
	return true
}

func knownEvaluationRisk(value string) bool {
	return value == "low" || value == "medium" || value == "high" || value == "critical"
}
