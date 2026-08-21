package securityagent

import (
	"sort"
	"strconv"
	"sync"
	"time"
)

type Template struct {
	ID, Name                 string
	Version                  int
	TriggerKind              string
	DefaultActions           []string
	VerificationCondition    string
	ApprovalRequired         map[string]bool
	AgentBound, SessionBound bool
	Count                    int
	Window                   time.Duration
}
type TemplateRegistry struct {
	mu     sync.RWMutex
	values map[string]Template
}

func NewTemplateRegistry(values []Template) (*TemplateRegistry, error) {
	registry := &TemplateRegistry{values: map[string]Template{}}
	for _, value := range values {
		if !validTemplate(value) {
			return nil, ErrRejected
		}
		key := templateKey(value.ID, value.Version)
		if _, ok := registry.values[key]; ok {
			return nil, ErrRejected
		}
		registry.values[key] = cloneTemplate(value)
	}
	return registry, nil
}
func (registry *TemplateRegistry) IDs() []string {
	if registry == nil {
		return []string{}
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	seen := map[string]bool{}
	for _, value := range registry.values {
		seen[value.ID] = true
	}
	result := make([]string, 0, len(seen))
	for id := range seen {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}
func (registry *TemplateRegistry) Get(id string, version int) (Template, error) {
	if registry == nil || !bounded(id, 128) || version <= 0 {
		return Template{}, ErrRejected
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	value, ok := registry.values[templateKey(id, version)]
	if !ok {
		return Template{}, ErrRejected
	}
	return cloneTemplate(value), nil
}
func BuiltInTemplates() []Template {
	return []Template{
		{ID: "finding_response", Name: "Finding Response", Version: 1, TriggerKind: "finding", DefaultActions: []string{"update_finding_response"}, VerificationCondition: "finding_state", ApprovalRequired: map[string]bool{"update_finding_response": true}},
		{ID: "suspicious_egress", Name: "Suspicious Egress", Version: 1, TriggerKind: "finding", DefaultActions: []string{"create_temporary_policy", "create_evidence_export", "send_response_webhook"}, VerificationCondition: "scoped_policy_blocked_and_evidence_exported", ApprovalRequired: map[string]bool{"create_temporary_policy": true}},
		{ID: "credential_exposure", Name: "Credential Exposure", Version: 1, TriggerKind: "finding", DefaultActions: []string{"create_temporary_policy", "revoke_integration_connection", "create_evidence_export"}, VerificationCondition: "credential_contained_or_needs_human", ApprovalRequired: map[string]bool{"create_temporary_policy": true, "revoke_integration_connection": true}},
		{ID: "prompt_tool_injection", Name: "Prompt or Tool Injection", Version: 1, TriggerKind: "attack_path", DefaultActions: []string{"create_temporary_policy", "run_test"}, VerificationCondition: "linked_risk_blocked_or_not_reproduced", ApprovalRequired: map[string]bool{"create_temporary_policy": true}},
		{ID: "repeated_policy_violation", Name: "Repeated Policy Violation", Version: 1, TriggerKind: "runtime_decision", DefaultActions: []string{"isolate_session", "create_evidence_export"}, VerificationCondition: "session_blocked_and_evidence_exported", ApprovalRequired: map[string]bool{"isolate_session": true}, AgentBound: true, SessionBound: true, Count: 3, Window: 5 * time.Minute},
		{ID: "shadow_agent_triage", Name: "Shadow Agent Triage", Version: 1, TriggerKind: "finding", DefaultActions: []string{"run_test", "create_evidence_export", "send_response_webhook"}, VerificationCondition: "evidence_collected_for_human_triage", ApprovalRequired: map[string]bool{}},
	}
}
func validTemplate(value Template) bool {
	if !bounded(value.ID, 128) || !bounded(value.Name, 256) || value.Version <= 0 || !contains([]string{"finding", "attack_path", "runtime_decision"}, value.TriggerKind) || !uniqueBounded(value.DefaultActions, 128) || !bounded(value.VerificationCondition, 256) {
		return false
	}
	for key, required := range value.ApprovalRequired {
		if !required || !contains(value.DefaultActions, key) {
			return false
		}
	}
	if value.TriggerKind == "runtime_decision" {
		return value.AgentBound && value.SessionBound && value.Count > 0 && value.Count <= 100 && value.Window > 0 && value.Window <= 24*time.Hour
	}
	return value.Count == 0 && value.Window == 0
}
func templateKey(id string, version int) string { return id + "#" + strconv.Itoa(version) }
func cloneTemplate(value Template) Template {
	value.DefaultActions = cloneStrings(value.DefaultActions)
	approvals := map[string]bool{}
	for key, item := range value.ApprovalRequired {
		approvals[key] = item
	}
	value.ApprovalRequired = approvals
	return value
}
