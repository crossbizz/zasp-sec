package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const activityAuditID = "pid_7b000003-0000-4000-8000-000000000003"
const activityAuditSQL = "SELECT zasp_production_security_agent_run_context_audit($1,$2,$3,$4,$5,$6,$7)"

func activityAuditWire(t *testing.T, identity RequestIdentity) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"id": activityAuditID, "run_id": "pid_7b000002-0000-4000-8000-000000000002",
		"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(),
		"actor_reference": "worker-activity-audit", "event_kind": "run_queued", "correlation_id": "pid_7b000004-0000-4000-8000-000000000004", "occurred_at": "2026-09-16T12:00:00.123456Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSecurityAgentAuditRepository(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.Permissions = []string{"view", "view_audit"}
	digest := sha256.Sum256([]byte("owned-browser-session"))
	db := &approvalContextDatabase{securityAgentRepositoryDatabase: &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{activityAuditSQL: activityAuditWire(t, identity)}}, available: true}
	repo := &PostgresRepository{database: db, securityAgentExecution: true}
	got, err := repo.GetSecurityAgentAuditEvent(context.Background(), identity, activityAuditID, digest[:])
	if err != nil || got.ID != activityAuditID || got.ActorReference != "worker-activity-audit" {
		t.Fatalf("audit read=%#v err=%v", got, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), digest[:], identity.CSRFToken, activityAuditID}
	if len(db.arguments) != 1 || !reflect.DeepEqual(db.arguments[0], want) {
		t.Fatalf("audit query arguments=%#v", db.arguments)
	}
	for _, tc := range []struct {
		name      string
		available bool
		failure   error
	}{{"unsupported", false, nil}, {"failed pin", true, errors.New("pin mismatch")}} {
		t.Run(tc.name, func(t *testing.T) {
			db.available = tc.available
			db.failure = tc.failure
			before := len(db.statements)
			if _, err := repo.GetSecurityAgentAuditEvent(context.Background(), identity, activityAuditID, digest[:]); err != ErrRepositoryUnavailable || len(db.statements) != before {
				t.Fatalf("untrusted release queried: %v", err)
			}
		})
	}
	db.available = true
	db.failure = nil
	for _, mutation := range []func(*RequestIdentity){func(v *RequestIdentity) { v.Permissions = []string{"view"} }, func(v *RequestIdentity) { v.CredentialKind = CredentialBearerToken }, func(v *RequestIdentity) { v.CSRFToken = "" }} {
		bad := identity
		mutation(&bad)
		before := len(db.statements)
		if _, err := repo.GetSecurityAgentAuditEvent(context.Background(), bad, activityAuditID, digest[:]); err == nil || len(db.statements) != before {
			t.Fatalf("invalid identity reached SQL: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := len(db.statements)
	if _, err := repo.GetSecurityAgentAuditEvent(ctx, identity, activityAuditID, digest[:]); !errors.Is(err, context.Canceled) || len(db.statements) != before {
		t.Fatalf("cancelled read: %v", err)
	}
}

func TestSecurityAgentAuditProjectionRefusesMalformedAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	original := activityAuditWire(t, identity)
	for _, tc := range []struct{ field, value string }{
		{"id", "pid_7b000099-0000-4000-8000-000000000099"}, {"organization_id", "pid_7b000099-0000-4000-8000-000000000099"},
		{"workspace_id", "pid_7b000099-0000-4000-8000-000000000099"}, {"environment_id", "pid_7b000099-0000-4000-8000-000000000099"},
		{"run_id", "invalid"}, {"correlation_id", "invalid"}, {"actor_reference", ""}, {"actor_reference", strings.Repeat("x", 129)},
		{"event_kind", "line\nbreak"}, {"occurred_at", "2026-09-16T12:00:00+01:00"}, {"occurred_at", "2026-09-16T12:00:00.123456789Z"}, {"body", "private"},
	} {
		t.Run(tc.field+tc.value, func(t *testing.T) {
			var obj map[string]string
			if err := json.Unmarshal(original, &obj); err != nil {
				t.Fatal(err)
			}
			obj[tc.field] = tc.value
			raw, _ := json.Marshal(obj)
			if _, err := decodeSecurityAgentAuditEvent(raw, identity, activityAuditID); err != ErrRepositoryUnavailable {
				t.Fatalf("malformed projection accepted: %v", err)
			}
		})
	}
	for _, raw := range []string{strings.Replace(string(original), "worker-activity-audit", `\ud800`, 1), strings.TrimSuffix(string(original), "}") + `,"id":"` + activityAuditID + `"}`, "null"} {
		if _, err := decodeSecurityAgentAuditEvent([]byte(raw), identity, activityAuditID); err != ErrRepositoryUnavailable {
			t.Fatalf("invalid JSON authority accepted: %v", err)
		}
	}
}
