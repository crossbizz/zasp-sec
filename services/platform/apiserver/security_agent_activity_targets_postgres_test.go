package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func exerciseSecurityAgentActivityTargets(t *testing.T, ctx context.Context, owner, api *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, digest []byte) {
	t.Helper()
	handler, handlerErr := NewSecurityAgentPublicHTTPHandler(repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
	if handlerErr != nil {
		t.Fatal(handlerErr)
	}
	cursors := make(map[string]string)
	read := func(kind, run, after string) (json.RawMessage, error) {
		var position any
		if after != "" {
			position = after
		}
		var raw json.RawMessage
		err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_targets($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), digest, identity.CSRFToken, kind, run, position, 1).Scan(&raw)
		if err == nil {
			request := SecurityAgentActivityTargetRequest{RunID: run, Kind: kind, AfterID: after, Limit: 1}
			page, repositoryErr := repository.ListSecurityAgentRunActivity(ctx, identity, request, digest)
			if repositoryErr != nil {
				t.Fatalf("registered forward repository: %v", repositoryErr)
			}
			want, decodeErr := decodeSecurityAgentActivityTargets(raw, request)
			if decodeErr != nil || !reflect.DeepEqual(page, want) {
				t.Fatalf("registered target page=%#v want=%#v %v", page, want, decodeErr)
			}
			cursor := cursors[kind+run+after]
			if after == "" || cursor != "" {
				httpRequest := workflowRequest(t, identity, "pid_7b000004-0000-4000-8000-000000000004", "listSecurityAgentRunActivity", map[string]string{"kind": kind, "id": run}, "GET", "/api/v1/security-agent-runs/"+run+"/activity/"+kind, "")
				httpRequest.URL.RawQuery = "limit=1"
				if cursor != "" {
					httpRequest.URL.RawQuery += "&cursor=" + url.QueryEscape(cursor)
				}
				httpRequest.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "activity-audit-session-" + identity.Scope.OrganizationID().String()[4:6]})
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httpRequest)
				var value struct {
					Items    []SecurityAgentActivityTarget `json:"items"`
					Coverage string                        `json:"coverage"`
					Next     string                        `json:"next_cursor"`
				}
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &value) != nil || !reflect.DeepEqual(value.Items, page.Items) || value.Coverage != page.Coverage || (value.Next == "") != (page.NextID == "") || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("forward HTTP integration=%d %s", response.Code, response.Body.String())
				}
				if value.Next != "" {
					cursors[kind+run+page.NextID] = value.Next
				}
			}
		}
		return raw, err
	}
	const run = "pid_7c000001-0000-4000-8000-000000000001"
	raw, err := read("finding", run, "")
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Context     json.RawMessage `json:"context"`
		AuditIDs    []string        `json:"audit_ids"`
		NextAuditID *string         `json:"next_audit_id"`
	}
	if json.Unmarshal(raw, &wire) != nil || wire.AuditIDs == nil || len(wire.AuditIDs) != 0 || wire.NextAuditID != nil {
		t.Fatalf("forward finding envelope=%s", raw)
	}
	page, err := projectSecurityAgentActivityTargets(wire.Context, run, "finding", "", 1)
	if err != nil || page.Coverage != "complete" || len(page.Items) != 1 || page.Items[0].ID != "pid_7c000099-0000-4000-8000-000000000099" {
		t.Fatalf("forward typed SQL projection=%#v %v", page, err)
	}
	const auditRun = "pid_7b000002-0000-4000-8000-000000000002"
	const auditID = "pid_7b000003-0000-4000-8000-000000000003"
	const secondAuditID = "pid_7b000006-0000-4000-8000-000000000006"
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) SELECT organization_id,workspace_id,environment_id,$3,correlation_id,run_id,actor_id,event_kind,event_digest,body FROM zasp_security_agent_audit WHERE organization_id=$1 AND audit_id=$2`, identity.Scope.OrganizationID().String(), auditID, secondAuditID); err != nil {
		t.Fatal(err)
	}
	raw, err = read("audit", auditRun, "")
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &wire) != nil || len(wire.AuditIDs) != 1 || wire.AuditIDs[0] != auditID || wire.NextAuditID == nil || *wire.NextAuditID != auditID {
		t.Fatalf("forward audit identity=%s", raw)
	}
	if _, err := decodeSecurityAgentRunContextEnvelope(wire.Context, auditRun); err != nil {
		t.Fatalf("audit page context not bound: %v", err)
	}
	raw, err = read("audit", auditRun, auditID)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &wire) != nil || len(wire.AuditIDs) != 1 || wire.AuditIDs[0] != secondAuditID || wire.NextAuditID != nil {
		t.Fatalf("forward audit continuation=%s", raw)
	}
	raw, err = read("audit", auditRun, secondAuditID)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &wire) != nil || len(wire.AuditIDs) != 0 || wire.NextAuditID != nil {
		t.Fatalf("forward audit final empty page=%s", raw)
	}
	validDigest := digest
	digest = []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	_, err = read("finding", run, "")
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "28000" {
		t.Fatalf("forward session binding bypass: %v", err)
	}
	digest = validDigest
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='simulated' WHERE organization_id=$1 AND run_id=$2`, identity.Scope.OrganizationID().String(), run); err != nil {
		t.Fatal(err)
	}
	if _, err := read("finding", run, ""); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("simulated forward run returned: %v", err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='queued' WHERE organization_id=$1 AND run_id=$2`, identity.Scope.OrganizationID().String(), run); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, identity.Scope.OrganizationID().String(), identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"session", "audit"} {
		_, err := read(kind, run, "")
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatalf("forward %s permission bypass: %v", kind, err)
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE organization_id=$1 AND principal_id=$2`, identity.Scope.OrganizationID().String(), identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := read("session", run, ""); err != nil {
		t.Fatalf("restored forward permission rejected: %v", err)
	}
	if _, err := read("finding", "pid_7c000098-0000-4000-8000-000000000098", ""); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("missing forward run: %v", err)
	}
	if _, err := repository.ListSecurityAgentRunActivity(ctx, identity, SecurityAgentActivityTargetRequest{RunID: "pid_7c000098-0000-4000-8000-000000000098", Kind: "finding", Limit: 1}, digest); err != ErrRepositoryNotFound {
		t.Fatalf("repository missing forward run: %v", err)
	}
	for _, kind := range []string{"manual", "unknown"} {
		_, err := read(kind, run, "")
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "22023" {
			t.Fatalf("invalid forward kind=%v", err)
		}
	}
}
