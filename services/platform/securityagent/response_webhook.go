package securityagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type ResponseWebhookEvidence struct {
	SourceKind        string `json:"source_kind"`
	SourceID          string `json:"source_id"`
	SourceVersion     int64  `json:"source_version"`
	AssociationDigest string `json:"association_digest"`
}
type ResponseWebhookPayload struct {
	SchemaVersion  int                       `json:"schema_version"`
	Type           string                    `json:"type"`
	DeliveryID     string                    `json:"delivery_id"`
	OrganizationID string                    `json:"organization_id"`
	WorkspaceID    string                    `json:"workspace_id"`
	EnvironmentID  string                    `json:"environment_id"`
	RunID          string                    `json:"run_id"`
	StepID         string                    `json:"step_id"`
	PlanHash       string                    `json:"plan_hash"`
	Evidence       []ResponseWebhookEvidence `json:"evidence"`
}
type ResponseWebhookReceipt struct {
	Outcome   string
	ErrorCode string
}

var ErrResponseWebhookPayload = errors.New("invalid response webhook payload")

// EncodeResponseWebhookPayload checks structure only. Repository source
// membership and approval authority must be established by the caller.
func EncodeResponseWebhookPayload(p ResponseWebhookPayload) ([]byte, string, error) {
	if p.SchemaVersion != 1 || p.Type != "security_agent.response" || !responseWebhookDigest(p.PlanHash) || len(p.Evidence) < 1 || len(p.Evidence) > 8 {
		return nil, "", ErrResponseWebhookPayload
	}
	for _, id := range []string{p.DeliveryID, p.OrganizationID, p.WorkspaceID, p.EnvironmentID, p.RunID, p.StepID} {
		if _, err := domain.ParseProductID(id); err != nil {
			return nil, "", ErrResponseWebhookPayload
		}
	}
	seen := make(map[string]bool, len(p.Evidence))
	previous := ""
	for _, e := range p.Evidence {
		validID := false
		switch e.SourceKind {
		case "manual":
			validID = responseWebhookHex(e.SourceID)
		case "run_audit":
			_, err := domain.ParseProductID(e.SourceID)
			validID = err == nil
		}
		identity := e.SourceKind + "/" + e.SourceID
		// A source may occur only once, so ordering by its first two tuple fields
		// also orders the full (kind, id, version, association digest) tuple.
		if !validID || e.SourceVersion < 1 || e.SourceVersion > 9007199254740991 || !responseWebhookDigest(e.AssociationDigest) || seen[identity] || identity <= previous {
			return nil, "", ErrResponseWebhookPayload
		}
		seen[identity] = true
		previous = identity
	}
	body, err := json.Marshal(p)
	if err != nil || len(body) > 16<<10 {
		return nil, "", ErrResponseWebhookPayload
	}
	digest := sha256.Sum256(body)
	return body, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func responseWebhookDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && responseWebhookHex(strings.TrimPrefix(s, "sha256:"))
}

// Match the installed run-source digest contract: lowercase, nonzero, 32 bytes.
func responseWebhookHex(s string) bool {
	if len(s) != 64 || s == strings.Repeat("0", 64) {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
