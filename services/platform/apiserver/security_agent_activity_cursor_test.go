package apiserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestSecurityAgentActivityCursorBinding(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	handler := &securityAgentPublicHTTPHandler{config: SecurityAgentPublicHandlerConfig{SigningKey: securityAgentTestSigningKey}}
	stamp := time.Date(2026, 9, 16, 12, 0, 0, 123456000, time.UTC)
	for _, direction := range []string{"runs", "targets"} {
		position := stamp
		if direction == "targets" {
			position = time.Time{}
		}
		cursor, err := handler.encodeActivityCursor(identity, direction, "finding", activityRelatedTarget, 10, position, runContextTestRunID)
		if err != nil || cursor == "" {
			t.Fatalf("%s cursor: %v", direction, err)
		}
		at, id, ok := handler.decodeActivityCursor(cursor, identity, direction, "finding", activityRelatedTarget, 10)
		if !ok || !at.Equal(position) || id != runContextTestRunID {
			t.Fatalf("%s roundtrip rejected", direction)
		}
		otherPrincipal := identity
		otherPrincipal.PrincipalID, _ = domain.ParseProductID("pid_78000099-0000-4000-8000-000000000099")
		if _, _, ok := handler.decodeActivityCursor(cursor, otherPrincipal, direction, "finding", activityRelatedTarget, 10); ok {
			t.Fatal("cursor crossed principal")
		}
		for _, changed := range []struct {
			direction, kind, id string
			limit               int
		}{
			{"runs", "session", activityRelatedTarget, 10}, {"targets", "session", activityRelatedTarget, 10},
			{direction, "finding", runContextTestRunID, 10}, {direction, "finding", activityRelatedTarget, 11},
		} {
			if _, _, ok := handler.decodeActivityCursor(cursor, identity, changed.direction, changed.kind, changed.id, changed.limit); ok {
				t.Fatal("cursor crossed request binding")
			}
		}
		otherDirection := "runs"
		if direction == "runs" {
			otherDirection = "targets"
		}
		if _, _, ok := handler.decodeActivityCursor(cursor, identity, otherDirection, "finding", activityRelatedTarget, 10); ok {
			t.Fatal("cursor crossed direction")
		}
		ids := []domain.ProductID{identity.Scope.OrganizationID(), identity.Scope.WorkspaceID(), identity.Scope.EnvironmentID()}
		for i := range ids {
			changed := append([]domain.ProductID(nil), ids...)
			changed[i] = otherPrincipal.PrincipalID
			other := identity
			other.Scope, _ = domain.NewScope(changed[0], changed[1], changed[2])
			if _, _, ok := handler.decodeActivityCursor(cursor, other, direction, "finding", activityRelatedTarget, 10); ok {
				t.Fatalf("cursor crossed scope%d", i)
			}
		}
		decoded, _ := base64.RawURLEncoding.DecodeString(cursor)
		decoded[len(decoded)-1] ^= 1
		for _, invalid := range []string{"", cursor + "=", base64.RawURLEncoding.EncodeToString(decoded)} {
			if _, _, ok := handler.decodeActivityCursor(invalid, identity, direction, "finding", activityRelatedTarget, 10); ok {
				t.Fatal("malformed or tampered cursor accepted")
			}
		}
	}
}

func TestSecurityAgentActivityCursorRejectsSignedMalformedPayload(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	handler := &securityAgentPublicHTTPHandler{config: SecurityAgentPublicHandlerConfig{SigningKey: securityAgentTestSigningKey}}
	stamp := time.Date(2026, 9, 16, 12, 0, 0, 123456000, time.UTC)
	cursor, err := handler.encodeActivityCursor(identity, "runs", "finding", activityRelatedTarget, 10, stamp, runContextTestRunID)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(cursor)
	original := decoded[:len(decoded)-sha256.Size]
	sign := func(payload []byte, domain string) string {
		mac := hmac.New(sha256.New, securityAgentTestSigningKey)
		_, _ = mac.Write([]byte(domain))
		_, _ = mac.Write(payload)
		return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
	}
	for _, tc := range []struct {
		field string
		value any
	}{
		{"v", 2}, {"op", "listSecurityAgentRuns"}, {"t", "2026-09-16T12:00:00Z"}, {"t", "2026-09-16T12:00:00.123456789Z"}, {"t", "2026-09-16T12:00:00.123456+00:00"}, {"t", "0000-09-16T12:00:00.123456Z"}, {"id", nil}, {"extra", "ignored"},
	} {
		var value map[string]any
		if json.Unmarshal(original, &value) != nil {
			t.Fatal("fixture")
		}
		value[tc.field] = tc.value
		payload, _ := json.Marshal(value)
		if _, _, ok := handler.decodeActivityCursor(sign(payload, securityAgentActivityCursorDomain), identity, "runs", "finding", activityRelatedTarget, 10); ok {
			t.Fatalf("signed malformed %s accepted", tc.field)
		}
	}
	for _, payload := range []string{strings.TrimSuffix(string(original), "}") + `,"v":1}`, strings.Replace(string(original), `"t":"2026-09-16T12:00:00.123456Z",`, "", 1), string(original) + ` {}`} {
		if _, _, ok := handler.decodeActivityCursor(sign([]byte(payload), securityAgentActivityCursorDomain), identity, "runs", "finding", activityRelatedTarget, 10); ok {
			t.Fatal("ambiguous signed JSON accepted")
		}
	}
	if _, _, ok := handler.decodeActivityCursor(sign(original, ""), identity, "runs", "finding", activityRelatedTarget, 10); ok {
		t.Fatal("other cursor domain accepted")
	}
	forward, err := handler.encodeActivityCursor(identity, "targets", "finding", activityRelatedTarget, 10, time.Time{}, runContextTestRunID)
	if err != nil {
		t.Fatal(err)
	}
	forwardBytes, _ := base64.RawURLEncoding.DecodeString(forward)
	nullTime := strings.Replace(string(forwardBytes[:len(forwardBytes)-sha256.Size]), `"t":""`, `"t":null`, 1)
	if _, _, ok := handler.decodeActivityCursor(sign([]byte(nullTime), securityAgentActivityCursorDomain), identity, "targets", "finding", activityRelatedTarget, 10); ok {
		t.Fatal("signed null forward timestamp accepted")
	}
	for _, tc := range []struct {
		direction string
		at        time.Time
		limit     int
	}{
		{"unknown", stamp, 10}, {"runs", time.Time{}, 10}, {"targets", stamp, 10}, {"runs", stamp.Add(time.Nanosecond), 10}, {"runs", stamp, 0}, {"runs", stamp, 101},
	} {
		if value, err := handler.encodeActivityCursor(identity, tc.direction, "finding", activityRelatedTarget, tc.limit, tc.at, runContextTestRunID); err == nil || value != "" {
			t.Fatal("invalid position encoded")
		}
	}
}
