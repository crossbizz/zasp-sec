package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAdministrationTimeAndEvidenceKeysetsTraverseBeyondResponseBoundsWithPostgres(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runner := runRound2Migrations(t, ctx, connection)
	_ = runner
	identity := fixtureRequestIdentity(t)
	organization, workspace, environment := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	identity.Permissions = []string{"view", "manage_identity", "view_audit", "investigate_sessions", "view_compliance"}
	for _, seed := range []struct {
		statement string
		args      []any
	}{
		{`SET TIME ZONE '-07:00'`, nil},
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Round two','round-two.invalid')`, []any{organization}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Active')`, []any{organization, workspace}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Active','production')`, []any{organization, workspace, environment}},
		{`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($2,$1,'round-two','member','security_admin')`, []any{organization, identity.PrincipalID.String()}},
		{`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($2,$1,$3,$4,'Active','["view","manage_identity","view_audit","investigate_sessions","view_compliance"]'::jsonb,true)`, []any{organization, identity.PrincipalID.String(), workspace, environment}},
		{`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('round-two-session','sha256'),'session-round-two',$2,$1,$3,$4,'["view"]'::jsonb,'cccccccccccccccccccccccccccccccc',transaction_timestamp(),transaction_timestamp()+interval '1 hour')`, []any{organization, identity.PrincipalID.String(), workspace, environment}},
		{`INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT $1,$2,$3,'pid_'||lpad(ordinal::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),$4,'round2.audit',$4,'succeeded','{}'::jsonb,'2026-08-19 00:00:00+00'::timestamptz+ordinal*interval '1 millisecond' FROM generate_series(1,151) ordinal`, []any{organization, workspace, environment, identity.PrincipalID.String()}},
		{`INSERT INTO zasp_session_events(organization_id,session_id,id,class,label,evidence_id,source,confidence,at) SELECT $1,'session-round-two','event-'||lpad(ordinal::text,4,'0'),'tool','event '||ordinal,'evidence-'||ordinal,'product','exact','2026-08-19 00:00:00+00'::timestamptz+ordinal*interval '1 millisecond' FROM generate_series(1,151) ordinal`, []any{organization}},
		{`INSERT INTO zasp_compliance_controls(organization_id,id,framework,name,fresh_until) VALUES($1,'round-two-control','SOC 2','Round two control',transaction_timestamp()+interval '1 day')`, []any{organization}},
		{`INSERT INTO zasp_compliance_evidence(organization_id,control_id,id,asset_id,source,at) SELECT $1,'round-two-control','evidence-'||lpad(ordinal::text,4,'0'),'asset-'||ordinal,'runtime',transaction_timestamp()+ordinal*interval '1 millisecond' FROM generate_series(1,151) ordinal`, []any{organization}},
		{`INSERT INTO zasp_compliance_controls(organization_id,id,framework,name,fresh_until) VALUES($1,'round-two-control-z','SOC 2','Second control',transaction_timestamp()+interval '1 day')`, []any{organization}},
		{`INSERT INTO zasp_compliance_evidence(organization_id,control_id,id,asset_id,source,at) VALUES($1,'round-two-control-z','evidence-0001','asset-duplicate-id','runtime',transaction_timestamp())`, []any{organization}},
	} {
		if _, err := connection.Exec(ctx, seed.statement, seed.args...); err != nil {
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

	traverse := func(operation, path string, parameters map[string]string, itemID func(json.RawMessage) string) map[string]struct{} {
		t.Helper()
		seen := map[string]struct{}{}
		cursor := ""
		for {
			target := path + "?limit=50"
			if cursor != "" {
				target += "&cursor=" + url.QueryEscape(cursor)
			}
			request := workflowRequest(t, identity, testCorrelationID, operation, parameters, http.MethodGet, target, "")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var page struct {
				Items    []json.RawMessage `json:"items"`
				PageInfo struct {
					NextCursor *string `json:"next_cursor"`
					HasMore    bool    `json:"has_more"`
				} `json:"page_info"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil {
				t.Fatalf("%s page = %d %s", operation, response.Code, response.Body.String())
			}
			for _, item := range page.Items {
				id := itemID(item)
				if _, duplicate := seen[id]; duplicate {
					t.Fatalf("%s duplicated %q", operation, id)
				}
				seen[id] = struct{}{}
			}
			if !page.PageInfo.HasMore {
				break
			}
			if page.PageInfo.NextCursor == nil {
				t.Fatalf("%s omitted continuation", operation)
			}
			cursor = *page.PageInfo.NextCursor
		}
		return seen
	}
	topID := func(item json.RawMessage) string {
		var value struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(item, &value)
		return value.ID
	}
	evidenceID := func(item json.RawMessage) string {
		var value struct {
			Control struct {
				ID string `json:"id"`
			} `json:"control"`
			Evidence []struct {
				ID string `json:"id"`
			} `json:"evidence"`
		}
		_ = json.Unmarshal(item, &value)
		if len(value.Evidence) != 1 {
			return ""
		}
		return value.Control.ID + "/" + value.Evidence[0].ID
	}
	for _, test := range []struct {
		operation, path string
		parameters      map[string]string
		id              func(json.RawMessage) string
	}{
		{operation: "listAuditEvents", path: "/api/v1/admin/audit-events", id: topID},
		{operation: "listSessionEvents", path: "/api/v1/sessions/session-round-two/events", parameters: map[string]string{"id": "session-round-two"}, id: topID},
		{operation: "listComplianceEvidence", path: "/api/v1/compliance/evidence", id: evidenceID},
	} {
		want := 151
		if test.operation == "listComplianceEvidence" {
			want = 152
		}
		if seen := traverse(test.operation, test.path, test.parameters, test.id); len(seen) != want {
			t.Fatalf("%s traversed %d/%d", test.operation, len(seen), want)
		}
	}
	controls, err := repository.ReadAdministration(ctx, identity, "listComplianceControls", map[string]string{"limit": "100"})
	var controlPage struct {
		Items []struct {
			EvidenceIDs []string `json:"evidence_ids"`
		} `json:"items"`
	}
	if err != nil || json.Unmarshal(controls, &controlPage) != nil || len(controlPage.Items) != 2 || len(controlPage.Items[0].EvidenceIDs) != 100 || len(controlPage.Items[1].EvidenceIDs) != 1 {
		t.Fatalf("bounded evidence summary = %s (%v)", controls, err)
	}
	_ = database.Close()
}

func TestWorkspaceOnboardingIsAtomicAndRollbackDriftFailsClosedWithPostgres(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runner := runRound2Migrations(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	organization, workspace, environment := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	identity.Permissions = []string{"view", "manage_identity"}
	for _, seed := range []struct {
		statement string
		args      []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Round two','round-two.invalid')`, []any{organization}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Active')`, []any{organization, workspace}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Active','production')`, []any{organization, workspace, environment}},
		{`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($2,$1,'round-two','member','security_admin')`, []any{organization, identity.PrincipalID.String()}},
		{`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($2,$1,$3,$4,'Active','["view","manage_identity"]'::jsonb,true)`, []any{organization, identity.PrincipalID.String(), workspace, environment}},
	} {
		if _, err := connection.Exec(ctx, seed.statement, seed.args...); err != nil {
			t.Fatal(err)
		}
	}
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	repository, _ := NewPostgresRepository(database)
	newWorkspace := "pid_55000002-0000-4000-8000-000000000002"
	newEnvironment := "pid_55000003-0000-4000-8000-000000000003"
	payload, err := repository.MutateAdministration(ctx, identity, administrationMutation{Operation: "createWorkspace", ID: newWorkspace, InitialEnvironmentID: newEnvironment, Name: "Research", AuditID: "pid_55000006-0000-4000-8000-000000000006"})
	if err != nil || !json.Valid(payload) {
		t.Fatalf("atomic onboarding = %s %v", payload, err)
	}
	var durable int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_workspaces workspace JOIN zasp_environments environment ON environment.organization_id=workspace.organization_id AND environment.workspace_id=workspace.id JOIN zasp_authorized_scopes scope ON scope.organization_id=environment.organization_id AND scope.workspace_id=environment.workspace_id AND scope.environment_id=environment.id JOIN zasp_data_controls controls ON controls.organization_id=environment.organization_id AND controls.workspace_id=environment.workspace_id AND controls.environment_id=environment.id JOIN zasp_core_payloads payload ON payload.organization_id=environment.organization_id AND payload.workspace_id=environment.workspace_id AND payload.environment_id=environment.id WHERE workspace.organization_id=$1 AND workspace.id=$2 AND environment.id=$3 AND scope.principal_id=$4 AND payload.operation='session_bootstrap:'||$4 AND payload.payload->>'correlation_id'='pid_55000006-0000-4000-8000-000000000006'`, organization, newWorkspace, newEnvironment, identity.PrincipalID.String()).Scan(&durable); err != nil || durable != 1 {
		t.Fatalf("durable onboarding graph = %d %v", durable, err)
	}
	additionalEnvironment := "pid_55000013-0000-4000-8000-000000000013"
	if _, err := repository.MutateAdministration(ctx, identity, administrationMutation{Operation: "createEnvironment", ID: additionalEnvironment, WorkspaceID: workspace, Name: "Development two", AuditID: "pid_55000016-0000-4000-8000-000000000016"}); err != nil {
		t.Fatalf("additional environment onboarding: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_environments environment JOIN zasp_authorized_scopes scope ON scope.organization_id=environment.organization_id AND scope.workspace_id=environment.workspace_id AND scope.environment_id=environment.id JOIN zasp_data_controls controls ON controls.organization_id=environment.organization_id AND controls.workspace_id=environment.workspace_id AND controls.environment_id=environment.id JOIN zasp_core_payloads payload ON payload.organization_id=environment.organization_id AND payload.workspace_id=environment.workspace_id AND payload.environment_id=environment.id WHERE environment.organization_id=$1 AND environment.workspace_id=$2 AND environment.id=$3 AND scope.principal_id=$4 AND payload.operation='session_bootstrap:'||$4 AND payload.payload->>'correlation_id'='pid_55000016-0000-4000-8000-000000000016'`, organization, workspace, additionalEnvironment, identity.PrincipalID.String()).Scan(&durable); err != nil || durable != 1 {
		t.Fatalf("durable additional environment graph = %d %v", durable, err)
	}
	for _, statement := range []string{`DELETE FROM zasp_admin_audit`, `DELETE FROM zasp_core_payloads`, `DELETE FROM zasp_data_controls`, `DELETE FROM zasp_authorized_scopes`, `DELETE FROM zasp_environments`, `DELETE FROM zasp_workspaces`, `DELETE FROM zasp_organizations`, `DELETE FROM zasp_identity_memberships`} {
		if _, err := connection.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_api_token_reveal_grants ADD COLUMN hostile_drift text`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownAPITokenRevealGrants(ctx); !errors.Is(err, migrations.ErrDatabase) {
		t.Fatalf("v8 drift rollback = %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 8 {
		t.Fatalf("v8 preserved = %d %v", version, err)
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_api_token_reveal_grants DROP COLUMN hostile_drift`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownAPITokenRevealGrants(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_compliance_controls ADD COLUMN hostile_drift text`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionAdministration(ctx); !errors.Is(err, migrations.ErrDatabase) {
		t.Fatalf("v7 drift rollback = %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 7 {
		t.Fatalf("v7 preserved = %d %v", version, err)
	}
	_ = database.Close()
}

func runRound2Migrations(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance, runner.UpProductionAdministration, runner.UpAPITokenRevealGrants}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("migration %d: %v", index+1, err)
		}
	}
	return runner
}
