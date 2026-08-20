package gatewaycontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const (
	GatewayAudience     = "runtime-gateway"
	PolicyAudience      = "runtime-gateway-policy"
	JSONMediaType       = "application/json"
	AuthorityPath       = "/internal/v1/runtime-gateway/authority"
	PolicyPathPrefix    = "/internal/v1/policy-bundles/"
	DecisionPath        = "/internal/v1/runtime/decisions"
	AuthorizationHeader = "Authorization"
	TimestampHeader     = "X-Zasp-Gateway-Timestamp"
	ContentSHA256Header = "X-Zasp-Content-SHA256"
	SignatureHeader     = "X-Zasp-Gateway-Signature"
)

var (
	keyIDPattern          = regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`)
	classificationPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,63}$`)
)

type Authority struct {
	OrganizationID       string
	WorkspaceID          string
	EnvironmentID        string
	DeviceID             string
	DeviceVersion        uint64
	ReplayFloor          uint64
	CredentialID         string
	CredentialGeneration uint64
	KeyID                string
	Algorithm            string
	PublicKey            ed25519.PublicKey
	Audience             string
	ExpiresAt            time.Time
}

type DecisionEvent struct {
	CredentialID   string            `json:"credential_id"`
	DeviceID       string            `json:"device_id"`
	EventID        string            `json:"event_id"`
	ExpectedFloor  uint64            `json:"expected_floor"`
	NextFloor      uint64            `json:"next_floor"`
	PolicyVersion  uint64            `json:"policy_version"`
	Decision       string            `json:"decision"`
	ActionKind     string            `json:"action_kind"`
	Classification map[string]string `json:"classification"`
	OccurredAt     time.Time         `json:"occurred_at"`
}

type Repository interface {
	Ready(context.Context) error
	Authority(context.Context, string) (Authority, error)
	Policy(context.Context, string, uint64) (*policy.GatewayPolicyEnvelope, error)
	Record(context.Context, DecisionEvent) error
}

func validAuthority(value Authority, credentialID string, now time.Time) bool {
	return validProductID(value.OrganizationID) && validProductID(value.WorkspaceID) && validProductID(value.EnvironmentID) &&
		validProductID(value.DeviceID) && validProductID(value.CredentialID) && value.CredentialID == credentialID &&
		value.DeviceVersion > 0 && value.CredentialGeneration > 0 && keyIDPattern.MatchString(value.KeyID) &&
		value.Algorithm == "Ed25519" && len(value.PublicKey) == ed25519.PublicKeySize && value.Audience == GatewayAudience &&
		validTime(value.ExpiresAt) && value.ExpiresAt.After(now)
}

func validDecisionEvent(value DecisionEvent) bool {
	if !validProductID(value.CredentialID) || !validProductID(value.DeviceID) || !validProductID(value.EventID) ||
		value.NextFloor != value.ExpectedFloor+1 || value.PolicyVersion == 0 ||
		value.Decision != "allow" && value.Decision != "monitor" && value.Decision != "block" ||
		value.ActionKind != "http" && value.ActionKind != "mcp" || !validTime(value.OccurredAt) || len(value.Classification) != 4 {
		return false
	}
	for _, key := range []string{"category", "route_class", "resource_class", "outcome"} {
		if !classificationPattern.MatchString(value.Classification[key]) {
			return false
		}
	}
	return true
}

func validProductID(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func sameAuthority(left, right Authority) bool {
	return left.OrganizationID == right.OrganizationID && left.WorkspaceID == right.WorkspaceID &&
		left.EnvironmentID == right.EnvironmentID && left.DeviceID == right.DeviceID &&
		left.DeviceVersion == right.DeviceVersion && left.ReplayFloor == right.ReplayFloor &&
		left.CredentialID == right.CredentialID && left.CredentialGeneration == right.CredentialGeneration &&
		left.KeyID == right.KeyID && left.Algorithm == right.Algorithm && bytes.Equal(left.PublicKey, right.PublicKey) &&
		left.Audience == right.Audience && left.ExpiresAt.Equal(right.ExpiresAt)
}

func cloneAuthority(value Authority) Authority {
	value.PublicKey = append(ed25519.PublicKey(nil), value.PublicKey...)
	return value
}

func cloneDecisionEvent(value DecisionEvent) DecisionEvent {
	value.Classification = cloneStrings(value.Classification)
	return value
}

func cloneStrings(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func boundedText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
