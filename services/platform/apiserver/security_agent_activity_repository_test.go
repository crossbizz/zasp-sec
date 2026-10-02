package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const activityRelatedSQL = `SELECT zasp_production_security_agent_run_context_related_runs($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
const activityRelatedTarget = "pid_78000005-0000-4000-8000-000000000005"

func activityRelatedWire(t *testing.T, envelope json.RawMessage, mutate func(map[string]any)) json.RawMessage {
	t.Helper()
	value := map[string]any{"items": []json.RawMessage{envelope}, "coverage": "complete", "next_created_at": nil, "next_id": nil}
	if mutate != nil {
		mutate(value)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSecurityAgentActivityDecodedAssociations(t *testing.T) {
	request := SecurityAgentActivityRunRequest{Kind: "finding", EntityID: activityRelatedTarget, Limit: 10}
	for _, tc := range []struct {
		kind, trigger string
		want          bool
	}{
		{"finding", "finding", true}, {"attack_path", "attack_path", true}, {"session", "runtime_decision", true},
		{"finding", "manual", false}, {"session", "finding", false}, {"attack_path", "manual", false},
	} {
		request.Kind = tc.kind
		envelope := runContextEnvelopeFixture(t, func(c, _ map[string]any) {
			c["trigger"] = map[string]any{"kind": tc.trigger, "id": activityRelatedTarget, "version": 1}
		})
		_, err := decodeSecurityAgentActivityRuns(activityRelatedWire(t, envelope, nil), request, "")
		if (err == nil) != tc.want {
			t.Fatalf("%s/%s association: %v", tc.kind, tc.trigger, err)
		}
	}
	for _, tc := range []struct {
		action, kind, args string
		want               bool
	}{
		{"update_finding_response", "finding", `{"target_id":"` + activityRelatedTarget + `","expected_version":1,"target_status":"under_review"}`, true},
		{"isolate_session", "session", `{"target_id":"` + activityRelatedTarget + `","session_id":"` + activityRelatedTarget + `","device_id":"pid_78000009-0000-4000-8000-000000000009","scope":"pid_78000003-0000-4000-8000-000000000003","ttl_seconds":60}`, true},
		{"create_temporary_policy", "finding", `{"target_id":"` + activityRelatedTarget + `","scope":"` + activityRelatedTarget + `","mode":"block","ttl_seconds":60}`, false},
		{"revoke_integration_connection", "finding", `{"target_id":"` + activityRelatedTarget + `","integration_id":"pid_78000009-0000-4000-8000-000000000009"}`, false},
		{"update_finding_response", "finding", `null`, false},
	} {
		request.Kind = tc.kind
		actions, detail := actionProjectionFixture(t, tc.action, "", [2]int{}, [2]int{}, func(_, step map[string]any) { step["arguments"] = json.RawMessage(tc.args) })
		envelope, err := json.Marshal(map[string]any{"detail": detail, "context": map[string]any{"trigger": nil, "planner_receipt": nil}, "action_details": actions})
		if err != nil {
			t.Fatal(err)
		}
		_, err = decodeSecurityAgentActivityRuns(activityRelatedWire(t, envelope, nil), request, "")
		if (err == nil) != tc.want {
			t.Fatalf("%s/%s association: %v", tc.action, tc.kind, err)
		}
	}
	request.Kind = "finding"
	raw := activityRelatedWire(t, runContextEnvelopeFixture(t, nil), nil)
	duplicate := strings.Replace(string(raw), `"coverage":"complete"`, `"coverage":"partial","coverage":"complete"`, 1)
	if _, err := decodeSecurityAgentActivityRuns([]byte(duplicate), request, ""); err == nil {
		t.Fatal("duplicate coverage accepted")
	}
}

func TestSecurityAgentActivityAuditAssociation(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.Permissions = []string{"view", "view_audit"}
	digest := sha256.Sum256([]byte("owned-audit-relation"))
	request := SecurityAgentActivityRunRequest{Kind: "audit", EntityID: activityAuditID, Limit: 10}
	audit := strings.Replace(string(activityAuditWire(t, identity)), "pid_7b000002-0000-4000-8000-000000000002", runContextTestRunID, 1)
	db := &approvalContextDatabase{securityAgentRepositoryDatabase: &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{activityAuditSQL: []byte(audit), activityRelatedSQL: activityRelatedWire(t, runContextEnvelopeFixture(t, nil), nil)}}, available: true}
	repo := &PostgresRepository{database: db, securityAgentExecution: true}
	if got, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, request, digest[:]); err != nil || len(got.Items) != 1 {
		t.Fatalf("exact audit association: %#v %v", got, err)
	}
	db.responses[activityAuditSQL] = activityAuditWire(t, identity)
	if _, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, request, digest[:]); err != ErrRepositoryUnavailable {
		t.Fatalf("foreign audit run accepted: %v", err)
	}
	db.responses[activityAuditSQL] = []byte(audit)
	db.responses[activityRelatedSQL] = activityRelatedWire(t, runContextEnvelopeFixture(t, nil), func(v map[string]any) { v["items"] = []json.RawMessage{} })
	request.BeforeCreatedAt = time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	request.BeforeID = runContextTestRunID
	if got, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, request, digest[:]); err != nil || len(got.Items) != 0 || got.NextID != "" {
		t.Fatalf("audit continuation past sole row: %#v %v", got, err)
	}
}

func TestSecurityAgentActivityContinuation(t *testing.T) {
	request := SecurityAgentActivityRunRequest{Kind: "finding", EntityID: activityRelatedTarget, Limit: 1}
	raw := activityRelatedWire(t, runContextEnvelopeFixture(t, nil), func(v map[string]any) {
		v["next_id"] = runContextTestRunID
		v["next_created_at"] = "2026-09-16T00:00:00.123456Z"
	})
	page, err := decodeSecurityAgentActivityRuns(raw, request, "")
	if err != nil || page.NextID != runContextTestRunID || page.NextCreatedAt == nil {
		t.Fatalf("valid continuation rejected: %#v %v", page, err)
	}
	request.BeforeCreatedAt = *page.NextCreatedAt
	request.BeforeID = page.NextID
	if _, err := decodeSecurityAgentActivityRuns(raw, request, ""); err != ErrRepositoryUnavailable {
		t.Fatalf("nonadvancing continuation accepted: %v", err)
	}
	request.BeforeCreatedAt = request.BeforeCreatedAt.Add(time.Second)
	if _, err := decodeSecurityAgentActivityRuns(raw, request, ""); err != nil {
		t.Fatalf("advancing continuation rejected: %v", err)
	}
}

func TestSecurityAgentActivityRepositoryTypedAssociation(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.Permissions = []string{"view", "view_audit", "investigate_sessions"}
	digest := sha256.Sum256([]byte("owned-relation-browser"))
	envelope := runContextEnvelopeFixture(t, nil)
	db := &approvalContextDatabase{securityAgentRepositoryDatabase: &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{activityRelatedSQL: activityRelatedWire(t, envelope, nil)}}, available: true}
	repo := &PostgresRepository{database: db, securityAgentExecution: true}
	request := SecurityAgentActivityRunRequest{Kind: "finding", EntityID: activityRelatedTarget, Limit: 10}
	got, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, request, digest[:])
	if err != nil || len(got.Items) != 1 || got.Items[0].ID != runContextTestRunID || got.Coverage != "complete" {
		t.Fatalf("typed relation=%#v error=%v", got, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), digest[:], identity.CSRFToken, "finding", activityRelatedTarget, nil, nil, 10}
	if len(db.arguments) != 1 || !reflect.DeepEqual(db.arguments[0], want) {
		t.Fatalf("relation arguments=%#v", db.arguments)
	}
	for _, kind := range []string{"attack_path", "session"} {
		request.Kind = kind
		if _, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, request, digest[:]); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("cross-kind candidate accepted: %s %v", kind, err)
		}
	}
	request.Kind = "finding"
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["items"] = nil },
		func(v map[string]any) { v["items"] = []json.RawMessage{envelope, envelope} },
		func(v map[string]any) { v["coverage"] = "unknown" },
		func(v map[string]any) { v["next_id"] = runContextTestRunID },
		func(v map[string]any) {
			v["next_created_at"] = "2026-09-16T00:00:00Z"
			v["next_id"] = activityRelatedTarget
		},
		func(v map[string]any) { v["unexpected"] = "private" },
	} {
		db.responses[activityRelatedSQL] = activityRelatedWire(t, envelope, mutate)
		if _, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, request, digest[:]); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("invalid page accepted: %v", err)
		}
	}
	db.responses[activityRelatedSQL] = activityRelatedWire(t, envelope, func(v map[string]any) { v["items"] = []json.RawMessage{}; v["coverage"] = "partial" })
	if got, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, request, digest[:]); err != nil || got.Coverage != "partial" || got.Items == nil || len(got.Items) != 0 {
		t.Fatalf("partial empty page lost: %#v %v", got, err)
	}
	for _, mutate := range []func(*RequestIdentity){
		func(v *RequestIdentity) { v.CredentialKind = CredentialBearerToken },
		func(v *RequestIdentity) { v.Permissions = []string{"view_audit"} },
		func(v *RequestIdentity) { v.CSRFToken = "" },
	} {
		bad := identity
		mutate(&bad)
		before := len(db.statements)
		if _, err := repo.ListSecurityAgentActivityRuns(context.Background(), bad, request, digest[:]); err == nil || len(db.statements) != before {
			t.Fatalf("invalid authority queried: %v", err)
		}
	}
	db.available = false
	before := len(db.statements)
	if _, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, request, digest[:]); err != ErrRepositoryUnavailable || len(db.statements) != before {
		t.Fatalf("unpinned release queried: %v", err)
	}
	db.available = true
	for _, badDigest := range [][]byte{nil, make([]byte, 32), []byte("short")} {
		before := len(db.statements)
		if _, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, request, badDigest); err != ErrRepositoryOperation || len(db.statements) != before {
			t.Fatalf("invalid digest reached SQL: %v", err)
		}
	}
	for _, mutate := range []func(*SecurityAgentActivityRunRequest){
		func(v *SecurityAgentActivityRunRequest) { v.Kind = "manual" },
		func(v *SecurityAgentActivityRunRequest) { v.EntityID = "invalid" },
		func(v *SecurityAgentActivityRunRequest) { v.Limit = 0 },
		func(v *SecurityAgentActivityRunRequest) { v.Limit = 101 },
		func(v *SecurityAgentActivityRunRequest) { v.BeforeID = runContextTestRunID },
	} {
		bad := request
		mutate(&bad)
		before := len(db.statements)
		if _, err := repo.ListSecurityAgentActivityRuns(context.Background(), identity, bad, digest[:]); err != ErrRepositoryOperation || len(db.statements) != before {
			t.Fatalf("invalid page request reached database: %v", err)
		}
	}
	for _, kind := range []string{"session", "audit"} {
		bad := identity
		bad.Permissions = []string{"view"}
		req := request
		req.Kind = kind
		before := len(db.statements)
		if _, err := repo.ListSecurityAgentActivityRuns(context.Background(), bad, req, digest[:]); err != ErrAuditExportForbidden || len(db.statements) != before {
			t.Fatalf("missing %s permission reached SQL: %v", kind, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	before = len(db.statements)
	if _, err := repo.ListSecurityAgentActivityRuns(cancelled, identity, request, digest[:]); !errors.Is(err, context.Canceled) || len(db.statements) != before {
		t.Fatalf("cancelled relation queried: %v", err)
	}
}
