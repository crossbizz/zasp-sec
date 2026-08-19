package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestTimestampKeysetsPreserveNativeOrderAcrossLosAngelesDSTFallback(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runRound2Migrations(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	organization, workspace, environment := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	identity.Permissions = []string{"view", "view_audit", "investigate_sessions"}
	for _, seed := range []struct {
		statement string
		arguments []any
	}{
		{`SET TIME ZONE 'America/Los_Angeles'`, nil},
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'DST organization','dst.invalid')`, []any{organization}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Active')`, []any{organization, workspace}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Active','production')`, []any{organization, workspace, environment}},
		{`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($2,$1,'dst-org','dst-member','security_admin')`, []any{organization, identity.PrincipalID.String()}},
		{`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($2,$1,$3,$4,'Active','["view","view_audit","investigate_sessions"]'::jsonb,true)`, []any{organization, identity.PrincipalID.String(), workspace, environment}},
		{`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('dst-session','sha256'),'session-dst',$2,$1,$3,$4,'["view"]'::jsonb,'dddddddddddddddddddddddddddddddd',transaction_timestamp(),transaction_timestamp()+interval '1 year')`, []any{organization, identity.PrincipalID.String(), workspace, environment}},
		{`INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,'pid_61000001-0000-4000-8000-000000000001',$4,'dst.audit',$4,'succeeded','{}'::jsonb,'2026-11-01T01:00:00-07:00'),($1,$2,$3,'pid_61000002-0000-4000-8000-000000000002',$4,'dst.audit',$4,'succeeded','{}'::jsonb,'2026-11-01T01:30:00-07:00'),($1,$2,$3,'pid_61000003-0000-4000-8000-000000000003',$4,'dst.audit',$4,'succeeded','{}'::jsonb,'2026-11-01T01:15:00-08:00')`, []any{organization, workspace, environment, identity.PrincipalID.String()}},
		{`INSERT INTO zasp_session_events(organization_id,session_id,id,class,label,evidence_id,source,confidence,at) VALUES($1,'session-dst','event-1','tool','first','evidence-1','product','exact','2026-11-01T01:00:00-07:00'),($1,'session-dst','event-2','tool','second','evidence-2','product','exact','2026-11-01T01:30:00-07:00'),($1,'session-dst','event-3','tool','third','evidence-3','product','exact','2026-11-01T01:15:00-08:00')`, []any{organization}},
	} {
		if _, err := connection.Exec(ctx, seed.statement, seed.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	handler := &identityHTTPHandler{administration: repository, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}

	traverse := func(operation, path string, parameters map[string]string) []string {
		t.Helper()
		var ids []string
		cursor := ""
		for requestCount := 0; requestCount < 4; requestCount++ {
			target := path + "?limit=1"
			if cursor != "" {
				target += "&cursor=" + url.QueryEscape(cursor)
			}
			request := workflowRequest(t, identity, testCorrelationID, operation, parameters, http.MethodGet, target, "")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var page struct {
				Items []struct {
					ID string `json:"id"`
				} `json:"items"`
				PageInfo struct {
					NextCursor *string `json:"next_cursor"`
					HasMore    bool    `json:"has_more"`
				} `json:"page_info"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 {
				t.Fatalf("%s page %d = %d %s", operation, requestCount+1, response.Code, response.Body.String())
			}
			ids = append(ids, page.Items[0].ID)
			if !page.PageInfo.HasMore {
				return ids
			}
			if page.PageInfo.NextCursor == nil {
				t.Fatalf("%s omitted continuation", operation)
			}
			cursor = *page.PageInfo.NextCursor
		}
		t.Fatalf("%s did not terminate", operation)
		return nil
	}
	if got, want := traverse("listAuditEvents", "/api/v1/admin/audit-events", nil), []string{"pid_61000003-0000-4000-8000-000000000003", "pid_61000002-0000-4000-8000-000000000002", "pid_61000001-0000-4000-8000-000000000001"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("audit native order = %v, want %v", got, want)
	}
	if got, want := traverse("listSessionEvents", "/api/v1/sessions/session-dst/events", map[string]string{"id": "session-dst"}), []string{"event-1", "event-2", "event-3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("session event native order = %v, want %v", got, want)
	}
	_ = database.Close()
}
