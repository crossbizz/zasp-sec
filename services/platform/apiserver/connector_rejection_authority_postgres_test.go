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
)

type connectorRejectionInvoke func(string, string, string, string, func(*http.Request)) *httptest.ResponseRecorder

func exerciseConnectorRejectionAuthority(t *testing.T, ctx context.Context, owner, api *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, integrationID string, invoke connectorRejectionInvoke, count func(*testing.T) int) {
	org, workspace, environment, actor := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	const body = `{"connector_key":"github","name":"Do not persist name","configuration":{"authorization_mode":"github_app","provider_url":"https://private.invalid/never-persist"}}`
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, append([]any{pgx.QueryExecModeSimpleProtocol}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	restore := func() {
		exec(`UPDATE zasp_identity_memberships SET active=true,role='security_engineer' WHERE organization_id=$1 AND principal_id=$2;
UPDATE zasp_product_sessions SET revoked_at=NULL,expires_at=clock_timestamp()+interval '1 hour' WHERE organization_id=$1 AND principal_id=$2;
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($2,$1,$3,$4,'connector-rejection','["view","manage_workflows"]') ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions=excluded.permissions;
UPDATE zasp_workflow_records SET deleted_at=NULL WHERE id=$5`, org, actor, workspace, environment, integrationID)
	}
	check := func(t *testing.T, w *httptest.ResponseRecorder, status, before, delta int) {
		t.Helper()
		if w.Code != status || count(t) != before+delta {
			t.Fatalf("status=%d want=%d audit delta=%d want=%d body=%s", w.Code, status, count(t)-before, delta, w.Body)
		}
		if strings.Contains(w.Body.String(), "private.invalid") {
			t.Fatal("response leaked URL")
		}
	}
	t.Run("retry_and_success_key_conflict", func(t *testing.T) {
		before := count(t)
		for n := 0; n < 2; n++ {
			check(t, invoke("POST", "/api/v1/integrations", body, "connector-retry-same-key", nil), 400, before, n+1)
		}
		check(t, invoke("POST", "/api/v1/integrations", body, "connector-safe-create-0001", nil), 409, before, 3)
		corrected := invoke("POST", "/api/v1/integrations", `{"connector_key":"github","name":"Corrected","configuration":{"authorization_mode":"github_app"}}`, "connector-retry-same-key", nil)
		if corrected.Code != 201 {
			t.Fatalf("rejection consumed success key: %d %s", corrected.Code, corrected.Body)
		}
	})
	t.Run("audit_read_API", func(t *testing.T) {
		const reader = "pid_6a000011-0000-4000-8000-000000000011"
		digest := sha256.Sum256([]byte("connector-audit-reader"))
		exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'organization-connector-reader','member-connector-reader','compliance_viewer');
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'reader','["view","view_audit"]');
INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","view_audit"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp())`, org, workspace, environment, reader, digest[:])
		w := invoke("GET", "/api/v1/audit-events?action=integration.setup.rejected&outcome=denied&limit=100", "", "", func(r *http.Request) { r.Header.Set("Cookie", browserSessionCookie+"=connector-audit-reader") })
		var page struct {
			Items []struct {
				Action   string         `json:"action"`
				Outcome  string         `json:"outcome"`
				Metadata map[string]any `json:"metadata"`
			} `json:"items"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 13 {
			t.Fatalf("public audit read status=%d %s", w.Code, w.Body)
		}
		for _, event := range page.Items {
			if event.Action != "integration.setup.rejected" || event.Outcome != "denied" {
				t.Fatalf("public rejected event: %+v", event)
			}
		}
		if strings.Contains(w.Body.String(), "private.invalid") || strings.Contains(w.Body.String(), "attacker.invalid") || strings.Contains(w.Body.String(), "Do not persist") {
			t.Fatal("audit API leaked submitted input")
		}
	})
	t.Run("token_permission_intersection", func(t *testing.T) {
		defer restore()
		digest := sha256.Sum256([]byte("connector-token-fixture"))
		exec(`INSERT INTO zasp_product_api_tokens(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES($5,$4,$1,$2,$3,'["view","manage_workflows"]',clock_timestamp()+interval '1 hour')`, org, workspace, environment, actor, digest[:])
		use := func(r *http.Request) {
			r.Header.Del("Cookie")
			r.Header.Del("Origin")
			r.Header.Del("X-CSRF-Token")
			r.Header.Set("Authorization", "Bearer connector-token-fixture")
		}
		before := count(t)
		check(t, invoke("POST", "/api/v1/integrations", body, "connector-token-allowed", use), 400, before, 1)
		exec(`UPDATE zasp_product_api_tokens SET permissions='["view"]' WHERE token_digest=$1`, digest[:])
		check(t, invoke("POST", "/api/v1/integrations", body, "connector-token-denied1", use), 403, before, 1)
		exec(`UPDATE zasp_product_api_tokens SET permissions='["view","manage_workflows"]' WHERE token_digest=$1`, digest[:])
		exec(`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, org, actor)
		check(t, invoke("POST", "/api/v1/integrations", body, "connector-token-denied2", use), 403, before, 1)
		for _, change := range []string{"revoked", "expired", "permission_removed"} {
			t.Run("blocked_INSERT_"+change, func(t *testing.T) {
				restore()
				exec(`UPDATE zasp_product_api_tokens SET revoked_at=NULL,expires_at=clock_timestamp()+interval '1 hour',permissions='["view","manage_workflows"]' WHERE token_digest=$1`, digest[:])
				before := count(t)
				w := connectorRejectionBlockedHTTP(t, ctx, owner, api, `LOCK TABLE zasp_admin_audit IN SHARE MODE`, nil, func(call context.Context) *httptest.ResponseRecorder {
					return invoke("POST", "/api/v1/integrations", body, "connector-token-wait-"+change, func(r *http.Request) { use(r); *r = *r.WithContext(call) })
				}, func(context.Context) {
					switch change {
					case "revoked":
						exec(`UPDATE zasp_product_api_tokens SET revoked_at=clock_timestamp() WHERE token_digest=$1`, digest[:])
					case "expired":
						exec(`UPDATE zasp_product_api_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE token_digest=$1`, digest[:])
					case "permission_removed":
						exec(`UPDATE zasp_product_api_tokens SET permissions='["view"]' WHERE token_digest=$1`, digest[:])
					}
				}, false)
				status := 401
				if change == "permission_removed" {
					status = 403
				}
				check(t, w, status, before, 0)
			})
		}
	})
	t.Run("blocked_INSERT_rechecks_authority", func(t *testing.T) {
		for _, tc := range []struct {
			name, sql string
			args      []any
			status    int
		}{
			{"revoked", `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE principal_id=$1`, []any{actor}, 401},
			{"expired", `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE principal_id=$1`, []any{actor}, 401},
			{"member_disabled", `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, []any{actor}, 403},
			{"role_removed", `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE principal_id=$1`, []any{actor}, 403},
			{"scope_removed", `DELETE FROM zasp_authorized_scopes WHERE principal_id=$1`, []any{actor}, 403},
			{"target_deleted", `UPDATE zasp_workflow_records SET deleted_at=clock_timestamp() WHERE id=$1`, []any{integrationID}, 404},
		} {
			t.Run(tc.name, func(t *testing.T) {
				restore()
				defer restore()
				before := count(t)
				w := connectorRejectionBlockedHTTP(t, ctx, owner, api, `LOCK TABLE zasp_admin_audit IN SHARE MODE`, nil, func(call context.Context) *httptest.ResponseRecorder {
					return invoke("PATCH", "/api/v1/integrations/"+integrationID, body, "connector-wait-"+tc.name, func(r *http.Request) { *r = *r.WithContext(call) })
				}, func(context.Context) { exec(tc.sql, tc.args...) }, false)
				check(t, w, tc.status, before, 0)
			})
		}
	})
	t.Run("audit_INSERT_cancellation", func(t *testing.T) {
		before := count(t)
		w := connectorRejectionBlockedHTTP(t, ctx, owner, api, `LOCK TABLE zasp_admin_audit IN SHARE MODE`, nil, func(call context.Context) *httptest.ResponseRecorder {
			return invoke("POST", "/api/v1/integrations", body, "connector-cancel-insert", func(r *http.Request) { *r = *r.WithContext(call) })
		}, nil, true)
		check(t, w, 503, before, 0)
	})
	t.Run("wall_clock_expiry_after_target_wait", func(t *testing.T) {
		restore()
		defer restore()
		exec(`UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE principal_id=$1`, actor)
		before := count(t)
		w := connectorRejectionBlockedHTTP(t, ctx, owner, api, `SELECT 1 FROM zasp_workflow_records WHERE id=$1 FOR UPDATE`, []any{integrationID}, func(call context.Context) *httptest.ResponseRecorder {
			return invoke("PATCH", "/api/v1/integrations/"+integrationID, body, "connector-clock-expiry", func(r *http.Request) { *r = *r.WithContext(call) })
		}, func(wait context.Context) {
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				var expired bool
				if err := owner.QueryRow(wait, `SELECT bool_and(expires_at<=clock_timestamp()) FROM zasp_product_sessions WHERE principal_id=$1`, actor).Scan(&expired); err != nil {
					t.Fatal(err)
				}
				if expired {
					return
				}
				select {
				case <-wait.Done():
					t.Fatal(wait.Err())
				case <-ticker.C:
				}
			}
		}, false)
		check(t, w, 401, before, 0)
	})
	t.Run("group_permission_and_registered_writers", func(t *testing.T) {
		defer restore()
		var groupCookie, groupCSRF string
		freshSession := func() {
			t.Helper()
			var err error
			groupCookie, err = repository.CreateSession(ctx, SessionGrant{PrincipalID: identity.PrincipalID, Scope: identity.Scope, Permissions: []string{"view", "manage_workflows"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: groupCookie})
			if err != nil || !stringIn("manage_workflows", fresh.Permissions...) {
				t.Fatalf("fresh group session: %v permissions=%v", err, fresh.Permissions)
			}
			groupCSRF = fresh.CSRFToken
		}
		groupInvoke := func(method, path, body, key string, change func(*http.Request)) *httptest.ResponseRecorder {
			return invoke(method, path, body, key, func(r *http.Request) {
				r.Header.Set("Cookie", browserSessionCookie+"="+groupCookie)
				r.Header.Set("X-CSRF-Token", groupCSRF)
				if change != nil {
					change(r)
				}
			})
		}
		exec(`DELETE FROM zasp_authorized_scopes WHERE principal_id=$1;
INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id) VALUES($2,'scim-group-test-connector','security_engineer',$3,$4)`, actor, org, workspace, environment)
		resolve := func(c *pgx.Conn, groups string) error {
			var raw json.RawMessage
			return c.QueryRow(ctx, `SELECT zasp_identity_admin_resolve_session('organization-connector-rejection','member-connector-rejection',$1::jsonb)`, groups).Scan(&raw)
		}
		if err := resolve(api, `["scim-group-test-connector"]`); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "connector-rejection-session"}); !errors.Is(err, ErrRepositoryAuthentication) {
			t.Fatalf("changed group membership must revoke previous session: %v", err)
		}
		freshSession()
		before := count(t)
		check(t, groupInvoke("POST", "/api/v1/integrations", body, "connector-group-allowed", nil), 400, before, 1)
		for _, change := range []string{"resolve_removes_group", "mapping_role_removed", "mapping_removed"} {
			t.Run(change, func(t *testing.T) {
				exec(`INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id) VALUES($1,'scim-group-test-connector','security_engineer',$2,$3) ON CONFLICT(organization_id,group_reference) DO UPDATE SET role='security_engineer'`, org, workspace, environment)
				if err := resolve(api, `["scim-group-test-connector"]`); err != nil {
					t.Fatal(err)
				}
				freshSession()
				other, err := pgx.ConnectConfig(ctx, api.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close(context.Background())
				before := count(t)
				w := connectorRejectionBlockedHTTP(t, ctx, owner, api, `LOCK TABLE zasp_admin_audit IN SHARE MODE`, nil, func(call context.Context) *httptest.ResponseRecorder {
					return groupInvoke("POST", "/api/v1/integrations", body, "connector-group-"+change, func(r *http.Request) { *r = *r.WithContext(call) })
				}, func(context.Context) {
					if change == "resolve_removes_group" {
						if err := resolve(other, `[]`); err != nil {
							t.Fatal(err)
						}
					} else if change == "mapping_removed" {
						exec(`DELETE FROM zasp_group_mappings WHERE organization_id=$1`, org)
					} else {
						exec(`UPDATE zasp_group_mappings SET role='read_only_viewer' WHERE organization_id=$1`, org)
					}
				}, false)
				status := 403
				if change == "resolve_removes_group" {
					status = 401
				}
				check(t, w, status, before, 0)
			})
		}
		// Both registered member-group writers must block behind the final
		// membership lock, observed while the audit waits on the update target.
		for _, writer := range []string{"resolve", "deprovision"} {
			t.Run(writer+"_serializes_on_membership", func(t *testing.T) {
				restore()
				exec(`DELETE FROM zasp_authorized_scopes WHERE principal_id=$1;INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id) VALUES($2,'scim-group-test-connector','security_engineer',$3,$4) ON CONFLICT(organization_id,group_reference) DO UPDATE SET role='security_engineer'`, actor, org, workspace, environment)
				if err := resolve(api, `["scim-group-test-connector"]`); err != nil {
					t.Fatal(err)
				}
				freshSession()
				other, err := pgx.ConnectConfig(ctx, api.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close(context.Background())
				writerCtx, stop := context.WithTimeout(ctx, 10*time.Second)
				defer stop()
				done := make(chan error, 1)
				writerStarted, writerJoined := false, false
				defer func() {
					stop()
					if writerStarted && !writerJoined {
						select {
						case <-done:
						case <-time.After(5 * time.Second):
							t.Error("registered writer did not join during cleanup")
						}
					}
				}()
				before := count(t)
				w := connectorRejectionBlockedHTTP(t, ctx, owner, api, `SELECT 1 FROM zasp_workflow_records WHERE id=$1 FOR UPDATE`, []any{integrationID}, func(call context.Context) *httptest.ResponseRecorder {
					return groupInvoke("PATCH", "/api/v1/integrations/"+integrationID, body, "connector-writer-"+writer, func(r *http.Request) { *r = *r.WithContext(call) })
				}, func(wait context.Context) {
					writerStarted = true
					go func() {
						var raw json.RawMessage
						var err error
						if writer == "resolve" {
							err = other.QueryRow(writerCtx, `SELECT zasp_identity_admin_resolve_session('organization-connector-rejection','member-connector-rejection','[]')`).Scan(&raw)
						} else {
							digest := sha256.Sum256([]byte("deprovision"))
							err = other.QueryRow(writerCtx, `SELECT zasp_identity_admin_reconcile_deprovision('project-connector','webhook-event-test-connector','organization-connector-rejection','member-connector-rejection',$1,'pid_8b000019-0000-4000-8000-000000000019')`, digest[:]).Scan(&raw)
						}
						done <- err
					}()
					connectorRejectionAwaitBlocker(t, wait, owner, other.PgConn().PID(), api.PgConn().PID())
				}, true)
				check(t, w, 503, before, 0)
				select {
				case err := <-done:
					writerJoined = true
					if err != nil {
						t.Fatal(err)
					}
				case <-writerCtx.Done():
					t.Fatal("registered writer did not join")
				}
			})
		}
	})
}

func connectorRejectionAwaitBlocker(t *testing.T, ctx context.Context, owner *pgx.Conn, pid, blocker uint32) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := owner.QueryRow(ctx, `SELECT $1::int=ANY(pg_blocking_pids($2::int))`, blocker, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("expected database blocker not observed")
		case <-ticker.C:
		}
	}
}

func connectorRejectionBlockedHTTP(t *testing.T, parent context.Context, owner, api *pgx.Conn, lockSQL string, args []any, call func(context.Context) *httptest.ResponseRecorder, change func(context.Context), cancelCall bool) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	started, joined := false, false
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
		cancel()
		if started && !joined {
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("HTTP did not join")
			}
		}
	}()
	if _, err = tx.Exec(ctx, lockSQL, args...); err != nil {
		t.Fatal(err)
	}
	started = true
	go func() { done <- call(ctx) }()
	connectorRejectionAwaitBlocker(t, ctx, owner, api.PgConn().PID(), blocker.PgConn().PID())
	if change != nil {
		change(ctx)
	}
	if cancelCall {
		if _, err = owner.Exec(ctx, `SELECT pg_cancel_backend($1)`, api.PgConn().PID()); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-done:
		joined = true
		return w
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP did not join after unblock")
	}
	return nil
}
