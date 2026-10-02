package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// This is an owned database proof with seeded sessions and immutable audit rows,
// not a live tenant, IdP, provider action or public HTTP endpoint proof.
func TestSecurityAgentActivityAuditRegisteredPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		const principal = "pid_7b000001-0000-4000-8000-000000000001"
		const run = "pid_7b000002-0000-4000-8000-000000000002"
		const audit = "pid_7b000003-0000-4000-8000-000000000003"
		const correlation = "pid_7b000004-0000-4000-8000-000000000004"
		csrf := strings.Repeat("a", 32)
		type scope struct {
			org, workspace, environment, actor string
			digest                             [32]byte
		}
		var scopes []scope
		for _, prefix := range []string{"6a", "9a"} {
			s := scope{"pid_" + prefix + "000001-0000-4000-8000-000000000001", "pid_" + prefix + "000002-0000-4000-8000-000000000002", "pid_" + prefix + "000003-0000-4000-8000-000000000003", "worker-activity-audit-" + prefix, sha256.Sum256([]byte("activity-audit-session-" + prefix))}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,$3,$4,'security_admin',true)`, s.org, principal, "organization-activity-audit-"+prefix, "member-activity-audit-"+prefix); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Activity audit fixture','["view","view_audit","investigate_sessions"]',true)`, principal, s.org, s.workspace, s.environment); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,session_id,authenticated_at) VALUES($1,$2,$3,$4,$5,'["view","view_audit"]',$6,clock_timestamp()+interval '1 hour',$7,clock_timestamp())`, s.digest[:], principal, s.org, s.workspace, s.environment, csrf, "session-activity-audit-"+prefix); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) SELECT organization_id,workspace_id,environment_id,$2,definition_id,definition_version,'pid_7b000005-0000-4000-8000-000000000005',$3,'queued' FROM zasp_security_agent_definitions WHERE organization_id=$1`, s.org, run, principal); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES($1,$2,$3,$4,$5,$6,$7,'run_queued',decode(repeat('a',64),'hex'),'{"secret":"raw-audit-body-sentinel"}')`, s.org, s.workspace, s.environment, audit, correlation, run, s.actor); err != nil {
				t.Fatal(err)
			}
			scopes = append(scopes, s)
		}
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.User = "security_agent_v33_api_login"
		api, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer api.Close(context.Background())
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentPostgresRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		identityFor := func(s scope) RequestIdentity {
			org, err := domain.ParseProductID(s.org)
			if err != nil {
				t.Fatal(err)
			}
			workspace, err := domain.ParseProductID(s.workspace)
			if err != nil {
				t.Fatal(err)
			}
			environment, err := domain.ParseProductID(s.environment)
			if err != nil {
				t.Fatal(err)
			}
			principalID, err := domain.ParseProductID(principal)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := domain.NewScope(org, workspace, environment)
			if err != nil {
				t.Fatal(err)
			}
			return RequestIdentity{PrincipalID: principalID, Scope: selected, Permissions: []string{"view", "view_audit"}, CSRFToken: csrf, CredentialKind: CredentialBrowserSession}
		}
		read := func(s scope, id string, digest []byte, csrfValue string) (json.RawMessage, error) {
			var raw json.RawMessage
			err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_audit($1,$2,$3,$4,$5,$6,$7)`, s.org, s.workspace, s.environment, principal, digest, csrfValue, id).Scan(&raw)
			return raw, err
		}
		for _, s := range scopes {
			handler, err := NewSecurityAgentPublicHTTPHandler(repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identityFor(s), correlation, "getSecurityAgentAuditEvent", map[string]string{"id": audit}, http.MethodGet, "/api/v1/security-agent-audit-events/"+audit, "")
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "activity-audit-session-" + s.org[4:6]})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var httpValue SecurityAgentAuditEvent
			if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(response.Body.Bytes(), &httpValue) != nil || httpValue.ActorReference != s.actor || httpValue.OrganizationID != s.org {
				t.Fatalf("registered repository HTTP response=%d %s", response.Code, response.Body.String())
			}
			valueFromRepository, err := repository.GetSecurityAgentAuditEvent(ctx, identityFor(s), audit, s.digest[:])
			if err != nil || valueFromRepository.ActorReference != s.actor || valueFromRepository.ID != audit {
				t.Fatalf("compiled-pin repository audit read: %#v %v", valueFromRepository, err)
			}
			raw, err := read(s, audit, s.digest[:], csrf)
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			if len(value) != 9 || value["id"] != audit || value["run_id"] != run || value["actor_reference"] != s.actor || value["organization_id"] != s.org || value["workspace_id"] != s.workspace || value["environment_id"] != s.environment || value["event_kind"] != "run_queued" || value["correlation_id"] != correlation || value["occurred_at"] == nil || strings.Contains(string(raw), "raw-audit-body-sentinel") {
				t.Fatalf("scoped audit projection mismatch: %s", raw)
			}
		}
		a, b := scopes[0], scopes[1]
		relationIdentity := identityFor(a)
		relationIdentity.Permissions = []string{"view", "view_audit", "investigate_sessions"}
		exerciseSecurityAgentActivityRelations(t, ctx, owner, api, repository, relationIdentity, a.org, a.workspace, a.environment, principal, a.digest[:], csrf)
		if _, err := repository.GetSecurityAgentAuditEvent(ctx, identityFor(a), "pid_7b000099-0000-4000-8000-000000000099", a.digest[:]); err != ErrRepositoryNotFound {
			t.Fatalf("repository missing audit: %v", err)
		}
		if _, err := read(a, "pid_7b000099-0000-4000-8000-000000000099", a.digest[:], csrf); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("missing audit: %v", err)
		}
		for _, tc := range []struct {
			name       string
			s          scope
			digest     []byte
			csrf, code string
		}{
			{"foreign session", a, b.digest[:], csrf, "28000"},
			{"mixed workspace", scope{a.org, b.workspace, a.environment, a.actor, a.digest}, a.digest[:], csrf, "28000"},
			{"mixed environment", scope{a.org, a.workspace, b.environment, a.actor, a.digest}, a.digest[:], csrf, "28000"},
			{"wrong CSRF", a, a.digest[:], strings.Repeat("b", 32), "42501"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := read(tc.s, audit, tc.digest, tc.csrf)
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != tc.code {
					t.Fatalf("unauthorized audit read: %v", err)
				}
			})
		}
		for _, tc := range []struct{ mutation, code string }{
			{`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, "42501"},
			{`UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, "42501"},
			{`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE organization_id=$1 AND principal_id=$2`, "28000"},
			{`UPDATE zasp_product_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND principal_id=$2`, "28000"},
		} {
			if _, err := owner.Exec(ctx, tc.mutation, a.org, principal); err != nil {
				t.Fatal(err)
			}
			_, err := read(a, audit, a.digest[:], csrf)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != tc.code {
				t.Fatalf("revoked audit authority accepted: %v", err)
			}
			_, repoErr := repository.GetSecurityAgentAuditEvent(ctx, identityFor(a), audit, a.digest[:])
			wantErr := ErrAuditExportForbidden
			if tc.code == "28000" {
				wantErr = ErrRepositoryAuthentication
			}
			if repoErr != wantErr {
				t.Fatalf("repository revoked authority error=%v want=%v", repoErr, wantErr)
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_admin',active=true WHERE organization_id=$1 AND principal_id=$2`, a.org, principal); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_product_sessions SET revoked_at=NULL,expires_at=clock_timestamp()+interval '1 hour' WHERE organization_id=$1 AND principal_id=$2`, a.org, principal); err != nil {
				t.Fatal(err)
			}
			if _, err := read(a, audit, a.digest[:], csrf); err != nil {
				t.Fatalf("restored authority rejected: %v", err)
			}
		}
		workerConfig := config.Copy()
		workerConfig.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, workerConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		var denied json.RawMessage
		err = worker.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_audit($1,$2,$3,$4,$5,$6,$7)`, a.org, a.workspace, a.environment, principal, a.digest[:], csrf, audit).Scan(&denied)
		var permissionError *pgconn.PgError
		if !errors.As(err, &permissionError) || permissionError.Code != "42501" {
			t.Fatalf("worker audit execution not denied: %v", err)
		}
		for _, tc := range []struct{ id, runID, state, actor, code string }{
			{"pid_7b000010-0000-4000-8000-000000000010", "pid_7b000011-0000-4000-8000-000000000011", "simulated", "worker-fixture", "missing"},
			{"pid_7b000012-0000-4000-8000-000000000012", "pid_7b000013-0000-4000-8000-000000000013", "queued", "", "55000"},
		} {
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) SELECT organization_id,workspace_id,environment_id,$2,definition_id,definition_version,trigger_id,requested_by,$3 FROM zasp_security_agent_runs WHERE organization_id=$1 AND run_id=$4`, a.org, tc.runID, tc.state, run); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES($1,$2,$3,$4,$4,$5,$6,'run_queued',decode(repeat('a',64),'hex'),'{}')`, a.org, a.workspace, a.environment, tc.id, tc.runID, tc.actor); err != nil {
				t.Fatal(err)
			}
			_, err := read(a, tc.id, a.digest[:], csrf)
			if tc.code == "missing" {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("simulated audit disclosed: %v", err)
				}
			} else {
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != tc.code {
					t.Fatalf("malformed audit not refused: %v", err)
				}
			}
		}
		// A caller must not make a drifted audit reader trusted by replacing the
		// metadata digest with the drifted live value. Compiled pins stay authoritative.
		if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_production_security_agent_run_context_audit(text,text,text,text,bytea,text,text) TO PUBLIC; UPDATE zasp_schema_metadata SET value=zasp_production_security_agent_run_context_live_fingerprint() WHERE key='production_security_agent_run_context_fingerprint'`); err != nil {
			t.Fatal(err)
		}
		if _, err := read(a, audit, a.digest[:], csrf); err == nil {
			t.Fatal("audit reader accepted drifted ACL and adopted live fingerprint")
		} else {
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "55000" {
				t.Fatalf("drift refusal: %v", err)
			}
		}
		if _, err := repository.GetSecurityAgentAuditEvent(ctx, identityFor(a), audit, a.digest[:]); err != ErrRepositoryUnavailable {
			t.Fatalf("application compiled pin accepted drift: %v", err)
		}
	})
}
