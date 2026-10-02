package securityagent

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode"
)

// TriggerRules is optional. Its absence retains the historical selector;
// explicit rules are versioned intent, never execution authorization.
type TriggerRules struct {
	Version         int              `json:"version"`
	Mode            string           `json:"mode"`
	CooldownSeconds int              `json:"cooldown_seconds,omitempty"`
	Finding         *FindingRules    `json:"finding,omitempty"`
	AttackPath      *AttackPathRules `json:"attack_path,omitempty"`
	Runtime         *RuntimeRules    `json:"runtime,omitempty"`
}
type FindingRules struct {
	Family          string `json:"family"`
	MinimumSeverity string `json:"minimum_severity"`
}
type AttackPathRules struct {
	State string `json:"state"`
}
type RuntimeRules struct {
	Decision      string `json:"decision"`
	Action        string `json:"action"`
	Risk          string `json:"risk,omitempty"`
	Count         int    `json:"count"`
	WindowSeconds int    `json:"window_seconds"`
}

func DecodeTriggerRules(raw json.RawMessage, kind, source string) (*TriggerRules, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > 2048 {
		return nil, ErrRejected
	}
	fields, err := triggerRuleObject(raw)
	if err != nil {
		return nil, err
	}
	var value TriggerRules
	if json.Unmarshal(raw, &value) != nil || value.Version != 1 {
		return nil, ErrRejected
	}
	if value.Mode == "manual" {
		if !triggerRuleKeys(fields, []string{"version", "mode"}, nil) {
			return nil, ErrRejected
		}
		return &value, nil
	}
	if value.Mode != "automatic" || value.CooldownSeconds < 1 || value.CooldownSeconds > 86400 {
		return nil, ErrRejected
	}
	nested := kind
	if kind == "runtime_decision" {
		nested = "runtime"
	}
	if !triggerRuleKeys(fields, []string{"version", "mode", "cooldown_seconds", nested}, nil) {
		return nil, ErrRejected
	}
	rule, err := triggerRuleObject(fields[nested])
	if err != nil {
		return nil, err
	}
	switch kind {
	case "finding":
		if !triggerRuleKeys(rule, []string{"family", "minimum_severity"}, nil) || value.Finding == nil || !triggerRuleText(value.Finding.Family) || value.Finding.Family != source || severityRank(value.Finding.MinimumSeverity) == 0 {
			return nil, ErrRejected
		}
	case "attack_path":
		if !triggerRuleKeys(rule, []string{"state"}, nil) || value.AttackPath == nil || !contains([]string{"potential", "observed", "verified"}, value.AttackPath.State) || value.AttackPath.State != source {
			return nil, ErrRejected
		}
	case "runtime_decision":
		if !triggerRuleKeys(rule, []string{"decision", "action", "count", "window_seconds"}, []string{"risk"}) || value.Runtime == nil {
			return nil, ErrRejected
		}
		r := value.Runtime
		if !contains([]string{"allow", "monitor", "block"}, r.Decision) || !triggerRuleText(r.Action) || r.Count < 1 || r.Count > 100 || r.WindowSeconds < 1 || r.WindowSeconds > 86400 {
			return nil, ErrRejected
		}
		if _, present := rule["risk"]; present && severityRank(r.Risk) == 0 {
			return nil, ErrRejected
		}
	default:
		return nil, ErrRejected
	}
	return &value, nil
}

func triggerRuleText(value string) bool {
	return len(value) > 0 && len(value) <= 64 && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

// Decode objects before struct decoding: JSON duplicate keys and case aliases
// must not become different authority after PostgreSQL jsonb canonicalization.
func triggerRuleObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrRejected
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, ErrRejected
		}
		key, ok := token.(string)
		if !ok {
			return nil, ErrRejected
		}
		if _, present := fields[key]; present {
			return nil, ErrRejected
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrRejected
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrRejected
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrRejected
	}
	return fields, nil
}
func triggerRuleKeys(fields map[string]json.RawMessage, required, optional []string) bool {
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	for key := range fields {
		if !contains(required, key) && !contains(optional, key) {
			return false
		}
	}
	return true
}
