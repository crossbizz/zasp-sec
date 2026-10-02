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

const activityTargetsSQL = `SELECT zasp_production_security_agent_run_context_targets($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

func activityTargetsWire(t *testing.T, envelope json.RawMessage, ids any, next any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"context": envelope, "audit_ids": ids, "next_audit_id": next})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSecurityAgentActivityTargetsAuditOrdering(t *testing.T) {
	envelope := activityTargetEnvelope(t, "update_finding_response", json.RawMessage(`null`), nil)
	request := SecurityAgentActivityTargetRequest{RunID: runContextTestRunID, Kind: "audit", Limit: 10}
	for _, ids := range [][]string{{activityAuditID, activityRelatedTarget}, {activityAuditID, activityAuditID}, {"invalid"}} {
		if _, err := decodeSecurityAgentActivityTargets(activityTargetsWire(t, envelope, ids, nil), request); err != ErrRepositoryUnavailable {
			t.Fatalf("unordered audit IDs accepted: %v", err)
		}
	}
	if page, err := decodeSecurityAgentActivityTargets(activityTargetsWire(t, envelope, []string{activityRelatedTarget, activityAuditID}, nil), request); err != nil || len(page.Items) != 2 {
		t.Fatalf("ascending audit IDs rejected: %#v %v", page, err)
	}
	wrongRun := request
	wrongRun.RunID = activityAuditID
	if _, err := decodeSecurityAgentActivityTargets(activityTargetsWire(t, envelope, []string{}, nil), wrongRun); err != ErrRepositoryUnavailable {
		t.Fatal("foreign run context accepted")
	}
	request.AfterID = activityAuditID
	if _, err := decodeSecurityAgentActivityTargets(activityTargetsWire(t, envelope, []string{activityAuditID}, nil), request); err != ErrRepositoryUnavailable {
		t.Fatal("nonexclusive audit continuation accepted")
	}
	request.AfterID = ""
	request.Kind = "finding"
	if _, err := decodeSecurityAgentActivityTargets(activityTargetsWire(t, envelope, []string{activityAuditID}, nil), request); err != ErrRepositoryUnavailable {
		t.Fatal("audit IDs crossed nonaudit projection")
	}
	valid := activityTargetsWire(t, envelope, []string{}, nil)
	duplicate := strings.TrimSuffix(string(valid), "}") + `,"next_audit_id":null}`
	if _, err := decodeSecurityAgentActivityTargets([]byte(duplicate), request); err != ErrRepositoryUnavailable {
		t.Fatal("duplicate forward authority field accepted")
	}
}

func TestSecurityAgentActivityTargetsRepository(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.Permissions = []string{"view", "view_audit", "investigate_sessions"}
	digest := sha256.Sum256([]byte("owned-forward-session"))
	envelope := activityTargetEnvelope(t, "update_finding_response", json.RawMessage(`null`), map[string]any{"kind": "finding", "id": activityRelatedTarget, "version": 1})
	db := &approvalContextDatabase{securityAgentRepositoryDatabase: &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{activityTargetsSQL: activityTargetsWire(t, envelope, []string{}, nil)}}, available: true}
	repo := &PostgresRepository{database: db, securityAgentExecution: true}
	request := SecurityAgentActivityTargetRequest{RunID: runContextTestRunID, Kind: "finding", Limit: 1}
	page, err := repo.ListSecurityAgentRunActivity(context.Background(), identity, request, digest[:])
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != activityRelatedTarget || page.Coverage != "partial" {
		t.Fatalf("forward repository=%#v %v", page, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), digest[:], identity.CSRFToken, "finding", runContextTestRunID, nil, 1}
	if len(db.arguments) != 1 || !reflect.DeepEqual(db.arguments[0], want) {
		t.Fatalf("forward SQL arguments=%#v", db.arguments)
	}
	request.Kind = "audit"
	db.responses[activityTargetsSQL] = activityTargetsWire(t, envelope, []string{activityAuditID}, activityAuditID)
	page, err = repo.ListSecurityAgentRunActivity(context.Background(), identity, request, digest[:])
	if err != nil || len(page.Items) != 1 || page.Items[0].Kind != "audit" || page.Items[0].ID != activityAuditID || page.NextID != activityAuditID || page.Coverage != "complete" {
		t.Fatalf("forward audit=%#v %v", page, err)
	}
	for _, raw := range []json.RawMessage{
		activityTargetsWire(t, envelope, nil, nil), activityTargetsWire(t, envelope, []string{"invalid"}, nil),
		activityTargetsWire(t, envelope, []string{activityAuditID, activityAuditID}, nil), activityTargetsWire(t, envelope, []string{}, activityAuditID),
		activityTargetsWire(t, envelope, []string{activityAuditID}, activityRelatedTarget), activityTargetsWire(t, json.RawMessage(`{}`), []string{}, nil),
	} {
		db.responses[activityTargetsSQL] = raw
		if _, err := repo.ListSecurityAgentRunActivity(context.Background(), identity, request, digest[:]); err != ErrRepositoryUnavailable {
			t.Fatalf("invalid target authority accepted: %v", err)
		}
	}
	db.responses[activityTargetsSQL] = activityTargetsWire(t, envelope, []string{}, nil)
	request.AfterID = activityAuditID
	if page, err := repo.ListSecurityAgentRunActivity(context.Background(), identity, request, digest[:]); err != nil || len(page.Items) != 0 || page.Items == nil || page.Coverage != "complete" {
		t.Fatalf("empty audit continuation=%#v %v", page, err)
	}
	for _, kind := range []string{"finding", "session", "audit"} {
		bad := identity
		bad.Permissions = nil
		request.Kind = kind
		before := len(db.statements)
		if _, err := repo.ListSecurityAgentRunActivity(context.Background(), bad, request, digest[:]); err == nil || len(db.statements) != before {
			t.Fatal("forward permission bypass")
		}
	}
	db.available = false
	before := len(db.statements)
	if _, err := repo.ListSecurityAgentRunActivity(context.Background(), identity, request, digest[:]); err != ErrRepositoryUnavailable || len(db.statements) != before {
		t.Fatalf("unsupported forward release queried: %v", err)
	}
	db.available = true
	for _, mutate := range []func(*RequestIdentity){func(v *RequestIdentity) { v.CredentialKind = CredentialBearerToken }, func(v *RequestIdentity) { v.CSRFToken = "" }} {
		bad := identity
		mutate(&bad)
		before := len(db.statements)
		if _, err := repo.ListSecurityAgentRunActivity(context.Background(), bad, request, digest[:]); err != ErrRepositoryAuthentication || len(db.statements) != before {
			t.Fatalf("invalid forward identity queried: %v", err)
		}
	}
	for _, kind := range []string{"session", "audit"} {
		bad := identity
		bad.Permissions = []string{"view"}
		req := request
		req.Kind = kind
		before := len(db.statements)
		if _, err := repo.ListSecurityAgentRunActivity(context.Background(), bad, req, digest[:]); err != ErrAuditExportForbidden || len(db.statements) != before {
			t.Fatalf("forward kind permission bypass: %v", err)
		}
	}
	for _, badDigest := range [][]byte{nil, make([]byte, 32), []byte("short")} {
		before := len(db.statements)
		if _, err := repo.ListSecurityAgentRunActivity(context.Background(), identity, request, badDigest); err != ErrRepositoryOperation || len(db.statements) != before {
			t.Fatalf("invalid forward digest queried: %v", err)
		}
	}
	for _, mutate := range []func(*SecurityAgentActivityTargetRequest){func(v *SecurityAgentActivityTargetRequest) { v.RunID = "bad" }, func(v *SecurityAgentActivityTargetRequest) { v.AfterID = "bad" }, func(v *SecurityAgentActivityTargetRequest) { v.Kind = "manual" }, func(v *SecurityAgentActivityTargetRequest) { v.Limit = 101 }, func(v *SecurityAgentActivityTargetRequest) { v.Limit = 0 }} {
		bad := request
		mutate(&bad)
		before := len(db.statements)
		if _, err := repo.ListSecurityAgentRunActivity(context.Background(), identity, bad, digest[:]); err != ErrRepositoryOperation || len(db.statements) != before {
			t.Fatalf("invalid forward request queried: %v", err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	before = len(db.statements)
	if _, err := repo.ListSecurityAgentRunActivity(cancelled, identity, request, digest[:]); !errors.Is(err, context.Canceled) || len(db.statements) != before {
		t.Fatalf("cancelled forward request queried: %v", err)
	}
}
