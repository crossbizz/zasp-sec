package securityagent

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

type TriggerEvent struct {
	OrganizationID, EnvironmentID, Kind, SourceID string
	Family, Severity, EvidenceState               string
	PolicyAction, Risk, AgentID, SessionID        string
	At                                            time.Time
}
type FindingTriggerRule struct {
	OrganizationID, EnvironmentID, Family, MinimumSeverity string
	Enabled                                                bool
}
type AttackPathTriggerRule struct {
	OrganizationID, EnvironmentID, EvidenceState string
	Enabled                                      bool
}
type RuntimeTriggerRule struct {
	OrganizationID, EnvironmentID, Action, Risk, AgentID, SessionID string
	Count                                                           int
	Window                                                          time.Duration
	Enabled                                                         bool
}

func MatchFinding(rule FindingTriggerRule, event TriggerEvent) bool {
	return rule.Enabled && validTriggerScope(rule.OrganizationID, rule.EnvironmentID, event) && event.Kind == "finding" && bounded(rule.Family, 64) && event.Family == rule.Family && severityRank(event.Severity) >= severityRank(rule.MinimumSeverity) && severityRank(rule.MinimumSeverity) > 0
}
func MatchAttackPath(rule AttackPathTriggerRule, event TriggerEvent) bool {
	return rule.Enabled && validTriggerScope(rule.OrganizationID, rule.EnvironmentID, event) && event.Kind == "attack_path" && contains([]string{"potential", "verified"}, rule.EvidenceState) && event.EvidenceState == rule.EvidenceState
}
func MatchRuntime(rule RuntimeTriggerRule, events []TriggerEvent, now time.Time) bool {
	if !rule.Enabled || !bounded(rule.OrganizationID, 128) || !bounded(rule.EnvironmentID, 128) || !bounded(rule.Action, 64) || !bounded(rule.Risk, 64) || !bounded(rule.AgentID, 128) || !bounded(rule.SessionID, 128) || rule.Count <= 0 || rule.Count > 100 || rule.Window <= 0 || rule.Window > 24*time.Hour || now.Location() != time.UTC {
		return false
	}
	count := 0
	for _, event := range events {
		if validTriggerScope(rule.OrganizationID, rule.EnvironmentID, event) && event.Kind == "runtime_decision" && event.PolicyAction == rule.Action && event.Risk == rule.Risk && event.AgentID == rule.AgentID && event.SessionID == rule.SessionID && event.At.Location() == time.UTC && !event.At.After(now) && !event.At.Before(now.Add(-rule.Window)) {
			count++
		}
	}
	return count >= rule.Count
}
func validTriggerScope(organizationID, environmentID string, event TriggerEvent) bool {
	return bounded(organizationID, 128) && bounded(environmentID, 128) && event.OrganizationID == organizationID && event.EnvironmentID == environmentID && event.At.Location() == time.UTC && !event.At.IsZero()
}
func severityRank(value string) int {
	switch value {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

type TriggerDeduplicator struct {
	mu     sync.Mutex
	claims map[string]time.Time
}

func NewTriggerDeduplicator() *TriggerDeduplicator {
	return &TriggerDeduplicator{claims: map[string]time.Time{}}
}
func (dedup *TriggerDeduplicator) Claim(event TriggerEvent, cooldown time.Duration, now time.Time) (string, bool, error) {
	if dedup == nil || cooldown <= 0 || cooldown > 24*time.Hour || now.Location() != time.UTC || !validTriggerEvent(event) {
		return "", false, ErrRejected
	}
	fingerprint := triggerFingerprint(event)
	dedup.mu.Lock()
	defer dedup.mu.Unlock()
	if expiry, ok := dedup.claims[fingerprint]; ok && now.Before(expiry) {
		return fingerprint, false, nil
	}
	dedup.claims[fingerprint] = now.Add(cooldown)
	return fingerprint, true, nil
}
func (dedup *TriggerDeduplicator) release(fingerprint string) {
	if dedup == nil || fingerprint == "" {
		return
	}
	dedup.mu.Lock()
	delete(dedup.claims, fingerprint)
	dedup.mu.Unlock()
}
func triggerFingerprint(event TriggerEvent) string {
	source := strings.Join([]string{event.OrganizationID, event.EnvironmentID, event.Kind, event.SourceID, event.Family, event.Severity, event.EvidenceState, event.PolicyAction, event.Risk, event.AgentID, event.SessionID}, "\x1f")
	digest := sha256.Sum256([]byte(source))
	return hex.EncodeToString(digest[:])
}
func validTriggerEvent(event TriggerEvent) bool {
	return bounded(event.OrganizationID, 128) && bounded(event.EnvironmentID, 128) && contains([]string{"finding", "attack_path", "runtime_decision"}, event.Kind) && bounded(event.SourceID, 128) && event.At.Location() == time.UTC && !event.At.IsZero()
}
func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
