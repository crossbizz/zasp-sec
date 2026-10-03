package securityagent

import "encoding/json"

// Zero is an omitted legacy selection. Explicit empty or null values never
// select Block; reject them before a JSON decoder can erase that distinction.
type TemporaryPolicyMode string

const (
	TemporaryPolicyMonitor TemporaryPolicyMode = "monitor"
	TemporaryPolicyBlock   TemporaryPolicyMode = "block"
)

func (mode *TemporaryPolicyMode) UnmarshalJSON(raw []byte) error {
	var value string
	if json.Unmarshal(raw, &value) != nil || value != "monitor" && value != "block" {
		return ErrRejected
	}
	*mode = TemporaryPolicyMode(value)
	return nil
}

func (mode TemporaryPolicyMode) Effective() TemporaryPolicyMode {
	if mode == "" {
		return TemporaryPolicyBlock
	}
	return mode
}
func (mode TemporaryPolicyMode) Valid() bool {
	return mode == "" || mode == TemporaryPolicyMonitor || mode == TemporaryPolicyBlock
}
