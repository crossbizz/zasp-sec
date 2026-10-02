package apiserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

const securityAgentActivityCursorDomain = "zasp-security-agent-activity-v1\x00"
const securityAgentActivityCursorMax = 2048

type securityAgentActivityCursor struct {
	Version        int    `json:"v"`
	OrganizationID string `json:"o"`
	WorkspaceID    string `json:"w"`
	EnvironmentID  string `json:"e"`
	PrincipalID    string `json:"p"`
	Operation      string `json:"op"`
	Direction      string `json:"d"`
	Kind           string `json:"k"`
	EntityID       string `json:"entity"`
	Limit          int    `json:"l"`
	CreatedAt      string `json:"t"`
	ID             string `json:"id"`
}

func activityCursorOperation(direction string) string {
	switch direction {
	case "runs":
		return "listSecurityAgentActivityRuns"
	case "targets":
		return "listSecurityAgentRunActivity"
	default:
		return ""
	}
}

func (handler *securityAgentPublicHTTPHandler) activityCursorRequestValid(identity RequestIdentity, direction, kind, entityID string, limit int) bool {
	return handler != nil && len(handler.config.SigningKey) >= 32 && len(handler.config.SigningKey) <= 4096 && validRequestIdentity(identity, true) && identity.CredentialKind == CredentialBrowserSession && activityCursorOperation(direction) != "" && stringIn(kind, "finding", "attack_path", "session", "audit") && validProductID(entityID) && limit >= 1 && limit <= 100
}

func (handler *securityAgentPublicHTTPHandler) encodeActivityCursor(identity RequestIdentity, direction, kind, entityID string, limit int, at time.Time, id string) (string, error) {
	if !handler.activityCursorRequestValid(identity, direction, kind, entityID, limit) || !validProductID(id) {
		return "", ErrRepositoryOperation
	}
	created := ""
	if direction == "runs" {
		if at.IsZero() || at.Location() != time.UTC || at.Year() < 1 || at.Year() > 9999 || at.Nanosecond()%1000 != 0 {
			return "", ErrRepositoryOperation
		}
		created = at.Format(auditListTimeLayout)
	} else if !at.IsZero() {
		return "", ErrRepositoryOperation
	}
	payload, err := json.Marshal(securityAgentActivityCursor{Version: 1, OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), PrincipalID: identity.PrincipalID.String(), Operation: activityCursorOperation(direction), Direction: direction, Kind: kind, EntityID: entityID, Limit: limit, CreatedAt: created, ID: id})
	if err != nil {
		return "", ErrRepositoryOperation
	}
	mac := hmac.New(sha256.New, handler.config.SigningKey)
	_, _ = mac.Write([]byte(securityAgentActivityCursorDomain))
	_, _ = mac.Write(payload)
	value := base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
	if len(value) > securityAgentActivityCursorMax {
		return "", ErrRepositoryOperation
	}
	return value, nil
}

func (handler *securityAgentPublicHTTPHandler) decodeActivityCursor(value string, identity RequestIdentity, direction, kind, entityID string, limit int) (time.Time, string, bool) {
	fail := func() (time.Time, string, bool) { return time.Time{}, "", false }
	if !handler.activityCursorRequestValid(identity, direction, kind, entityID, limit) || len(value) < 2 || len(value) > securityAgentActivityCursorMax {
		return fail()
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) <= sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return fail()
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, handler.config.SigningKey)
	_, _ = mac.Write([]byte(securityAgentActivityCursorDomain))
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return fail()
	}
	fields, err := auditExportClosedObject(payload, securityAgentActivityCursorMax, "v", "o", "w", "e", "p", "op", "d", "k", "entity", "l", "t", "id")
	if err != nil {
		return fail()
	}
	// Forward cursors deliberately encode an empty string, never an unknown/null
	// timestamp. Go's ordinary string decoder alone conflates those two values.
	var timestamp *string
	if json.Unmarshal(fields["t"], &timestamp) != nil || timestamp == nil {
		return fail()
	}
	var cursor securityAgentActivityCursor
	if decodeStrictDiscovery(payload, &cursor) != nil || cursor.Version != 1 || cursor.OrganizationID != identity.Scope.OrganizationID().String() || cursor.WorkspaceID != identity.Scope.WorkspaceID().String() || cursor.EnvironmentID != identity.Scope.EnvironmentID().String() || cursor.PrincipalID != identity.PrincipalID.String() || cursor.Operation != activityCursorOperation(direction) || cursor.Direction != direction || cursor.Kind != kind || cursor.EntityID != entityID || cursor.Limit != limit || !validProductID(cursor.ID) {
		return fail()
	}
	if direction == "targets" {
		if cursor.CreatedAt != "" {
			return fail()
		}
		return time.Time{}, cursor.ID, true
	}
	at, valid := auditListTime(cursor.CreatedAt)
	if !valid || at.IsZero() || at.Format(auditListTimeLayout) != cursor.CreatedAt {
		return fail()
	}
	return at, cursor.ID, true
}
