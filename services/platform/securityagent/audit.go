package securityagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

type AuditEvent struct {
	Kind, OrganizationID, AgentID, RunID, PlanHash string
	Metadata                                       map[string]string
	At                                             time.Time
}

func BuildAuditEvent(kind, organizationID, agentID, runID string, plan Plan, metadata map[string]string, at time.Time) (AuditEvent, error) {
	if !contains([]string{"trigger", "plan", "authorization", "approval", "execute", "verify", "terminal"}, kind) || !bounded(organizationID, 128) || !bounded(agentID, 128) || !bounded(runID, 128) || at.IsZero() || at.Location() != time.UTC || len(metadata) > 32 {
		return AuditEvent{}, ErrRejected
	}
	clean := make(map[string]string, len(metadata))
	for key, value := range metadata {
		lower := strings.ToLower(key)
		if !bounded(key, 64) || !bounded(value, 256) || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "credential") || strings.Contains(lower, "argument") || strings.Contains(lower, "parameter") || strings.Contains(lower, "raw") {
			return AuditEvent{}, ErrRejected
		}
		clean[key] = value
	}
	planHash := ""
	if plan.Version != 0 || plan.Summary != "" || len(plan.Steps) != 0 {
		encoded, err := json.Marshal(plan)
		if err != nil || len(encoded) > 64*1024 {
			return AuditEvent{}, ErrRejected
		}
		digest := sha256.Sum256(encoded)
		planHash = hex.EncodeToString(digest[:])
	}
	return AuditEvent{Kind: kind, OrganizationID: organizationID, AgentID: agentID, RunID: runID, PlanHash: planHash, Metadata: clean, At: at}, nil
}
