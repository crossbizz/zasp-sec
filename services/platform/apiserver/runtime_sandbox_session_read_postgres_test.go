package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const sandboxSessionEventPageSQL = `SELECT zasp_runtime_sandbox_session_event_page($1,$2,$3,$4,$5,$6,$7,$8)`
const sandboxSessionEventGetSQL = `SELECT zasp_runtime_sandbox_session_event_get($1,$2,$3,$4,$5,$6)`

func sandboxSessionAPI(t *testing.T, ctx context.Context, admin *pgx.Conn) *pgx.Conn {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	org, workspace, environment, principal := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,'sandbox-org','sandbox-member','security_admin',true) ON CONFLICT(organization_id,principal_id) DO UPDATE SET role='security_admin',active=true`, org, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($4,$1,$2,$3,'Sandbox read proof','["view","investigate_sessions"]',true) ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions='["view","investigate_sessions"]'`, org, workspace, environment, principal); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "invocation_discovery_api"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { api.Close(context.Background()) })
	return api
}

func TestRuntimeSandboxSessionReadRetainsScopedBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, projected := seedSessionProjectionCompletionVersion(t, ctx, admin, true)
	var completed json.RawMessage
	if err := coordinator.QueryRow(ctx, sandboxSessionFinishSQL, args...).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	api := sandboxSessionAPI(t, ctx, admin)
	handler := sandboxSessionHTTPHandler(t, api)
	identity := fixtureRequestIdentity(t)
	scope := []any{args[0], args[1], args[2], identity.PrincipalID.String()}
	for _, item := range projected.Items {
		target := item.SessionID.String()
		if target == "" {
			target = "unattributed"
		}
		readArgs := append(append([]any(nil), scope...), target, item.EventID.String())
		var body json.RawMessage
		if err := api.QueryRow(ctx, sandboxSessionEventGetSQL, readArgs...).Scan(&body); err != nil {
			t.Fatal("sandbox event get rejected", err)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		if item.SandboxID != "" {
			if string(result["sandbox_id"]) != `"session-sandbox"` || string(result["sandbox_source_sensor_id"]) != `"`+sandboxSemantic+`"` {
				t.Fatal("API lost retained binding", string(body))
			}
		} else if result["sandbox_id"] != nil || result["sandbox_source_sensor_id"] != nil {
			t.Fatal("API invented unknown binding")
		}
		var page json.RawMessage
		pageArgs := append(append([]any(nil), scope...), target, nil, "", 101)
		if err := api.QueryRow(ctx, sandboxSessionEventPageSQL, pageArgs...).Scan(&page); err != nil {
			t.Fatal(err)
		}
		var entries struct {
			Items []map[string]json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(page, &entries); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries.Items {
			if string(entry["id"]) == string(result["id"]) {
				found = true
				left, _ := json.Marshal(entry)
				right, _ := json.Marshal(result)
				if string(left) != string(right) {
					t.Fatal("page/detail mismatch")
				}
			}
		}
		if !found {
			t.Fatal("page omitted retained event")
		}
		response := sandboxSessionHTTPRequest(t, handler, identity, "getSessionEvent", target, item.EventID.String(), "")
		var httpEvent map[string]json.RawMessage
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &httpEvent) != nil || string(httpEvent["sandbox_id"]) != string(result["sandbox_id"]) || string(httpEvent["sandbox_source_sensor_id"]) != string(result["sandbox_source_sensor_id"]) || string(httpEvent["confidence"]) != string(result["confidence"]) || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("HTTP lost canonical binding", response.Code, response.Body.String())
		}
		var legacy json.RawMessage
		if err := api.QueryRow(ctx, postgresRuntimeSessionEventGetSQL, readArgs...).Scan(&legacy); err != nil {
			t.Fatal(err)
		}
		var old map[string]json.RawMessage
		if err := json.Unmarshal(legacy, &old); err != nil {
			t.Fatal(err)
		}
		if old["sandbox_id"] != nil || old["sandbox_source_sensor_id"] != nil {
			t.Fatal("old representation changed")
		}
		requireSandboxSQLState(t, worker.QueryRow(ctx, sandboxSessionEventGetSQL, readArgs...).Scan(&body), "42501")
		for _, position := range []int{0, 1, 2, 3, 4, 5} {
			wrong := append([]any(nil), readArgs...)
			wrong[position] = "pid_99000001-0000-4000-8000-000000000001"
			if err := api.QueryRow(ctx, sandboxSessionEventGetSQL, wrong...).Scan(&body); err != nil || string(body) != "" && string(body) != "null" {
				t.Fatal("foreign/missing target disclosed event", position, string(body), err)
			}
		}
	}
	// Traverse the real HTTP cursor path, not just an unpaged SQL collection.
	cursor, seen := "", map[string]bool{}
	for i := 0; i < 3; i++ {
		query := "limit=1"
		if cursor != "" {
			query += "&cursor=" + url.QueryEscape(cursor)
		}
		response := sandboxSessionHTTPRequest(t, handler, identity, "listSessionEvents", "pid_96000007-0000-4000-8000-000000000007", "", query)
		var page struct {
			Items []struct {
				ID         string `json:"id"`
				Sandbox    string `json:"sandbox_id"`
				Sensor     string `json:"sandbox_source_sensor_id"`
				Confidence string `json:"confidence"`
			} `json:"items"`
			Info struct {
				Cursor *string `json:"next_cursor"`
				More   bool    `json:"has_more"`
			} `json:"page_info"`
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 {
			t.Fatal("HTTP page failed", response.Code, response.Body.String())
		}
		item := page.Items[0]
		if seen[item.ID] || item.Sandbox != "session-sandbox" || item.Sensor != sandboxSemantic || item.Confidence != "exact" && item.Confidence != "strong" {
			t.Fatal("cursor lost binding", response.Body.String())
		}
		seen[item.ID] = true
		if !page.Info.More {
			if page.Info.Cursor != nil {
				t.Fatal("terminal cursor retained")
			}
			break
		}
		if page.Info.Cursor == nil {
			t.Fatal("missing continuation")
		}
		cursor = *page.Info.Cursor
	}
	if len(seen) != 2 {
		t.Fatal("HTTP cursor omitted known event")
	}
	var body json.RawMessage
	invalidPage := append(append([]any(nil), scope...), "unattributed", nil, "", 102)
	requireSandboxSQLState(t, api.QueryRow(ctx, sandboxSessionEventPageSQL, invalidPage...).Scan(&body), "22023")
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('b',64) WHERE key='production_runtime_sandbox_binding_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	validPage := append(append([]any(nil), scope...), "unattributed", nil, "", 1)
	requireSandboxSQLState(t, api.QueryRow(ctx, sandboxSessionEventPageSQL, validPage...).Scan(&body), "55000")
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_sandbox_binding_fingerprint'`, migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1 AND organization_id=$2`, identity.PrincipalID.String(), args[0]); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, sandboxSessionEventPageSQL, validPage...).Scan(&body); err != nil || string(body) != "" && string(body) != "null" {
		t.Fatal("revoked scope disclosed page", string(body), err)
	}
	response := sandboxSessionHTTPRequest(t, handler, identity, "listSessionEvents", "unattributed", "", "limit=1")
	if response.Code != 404 || decodeErrorCode(t, response) != "not_found" {
		t.Fatal("HTTP revocation failed", response.Code, response.Body.String())
	}
}

func sandboxSessionHTTPHandler(t *testing.T, api *pgx.Conn) *identityHTTPHandler {
	t.Helper()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	// Match the production constructor. Its search provider is unused by the
	// event page/detail routes exercised here; all event data comes from PG.
	repository, err := NewPostgresRepositoryWithRuntimeSessionSearch(database, &sessionQueryIndex{})
	if err != nil {
		t.Fatal(err)
	}
	return &identityHTTPHandler{administration: repository, signingKey: []byte(strings.Repeat("s", 32)), now: time.Now}
}

func sandboxSessionHTTPRequest(t *testing.T, handler *identityHTTPHandler, identity RequestIdentity, operation, target, event, query string) *httptest.ResponseRecorder {
	t.Helper()
	identity.Permissions = append(identity.Permissions, "investigate_sessions")
	parameters := map[string]string{"id": target}
	path := "/api/v1/sessions/" + target + "/events"
	if event != "" {
		path += "/" + event
		parameters["eventId"] = event
	}
	if query != "" {
		path += "?" + query
	}
	request := workflowRequest(t, identity, testCorrelationID, operation, parameters, http.MethodGet, path, "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestRuntimeSandboxSessionAPIPrestageAndMissingAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, projected := seedSessionProjectionCompletion(t, ctx, admin)
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	api := sandboxSessionAPI(t, ctx, admin)
	handler := sandboxSessionHTTPHandler(t, api)
	identity := fixtureRequestIdentity(t)
	var before string
	for _, upgrade := range []bool{false, true} {
		if upgrade {
			installRuntimeSandboxDraft(t, ctx, admin)
		}
		for _, item := range projected.Items {
			target := item.SessionID.String()
			if target == "" {
				target = "unattributed"
			}
			response := sandboxSessionHTTPRequest(t, handler, identity, "getSessionEvent", target, item.EventID.String(), "")
			if response.Code != 200 || strings.Contains(response.Body.String(), "sandbox_id") || strings.Contains(response.Body.String(), "sandbox_source_sensor_id") {
				t.Fatal("historical API representation changed", response.Code, response.Body.String())
			}
			if item == projected.Items[0] {
				if upgrade && response.Body.String() != before {
					t.Fatal("same API binary changed historical bytes")
				}
				before = response.Body.String()
			}
		}
	}
	if _, err := admin.Exec(ctx, `DROP FUNCTION zasp_production_runtime_sandbox_binding_readiness(text,text)`); err != nil {
		t.Fatal(err)
	}
	response := sandboxSessionHTTPRequest(t, handler, identity, "listSessionEvents", "unattributed", "", "limit=1")
	if response.Code != 503 || decodeErrorCode(t, response) != "provider_unavailable" {
		t.Fatal("missing50 authority downgraded", response.Code, response.Body.String())
	}
	if err := handler.administration.(*PostgresRepository).Ready(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatal("missing50 accepted API readiness", err)
	}
}

func TestRuntimeSandboxSessionAPIRejectsPredecessorMetadataDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	api := sandboxSessionAPI(t, ctx, admin)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.SchemaVersion(ctx); err != nil {
		t.Fatal("healthy50 startup failed", err)
	}
	for _, release := range []struct {
		version       int
		key, checksum string
	}{
		{49, "production_runtime_correlation_routing_checksum", migrations.ProductionRuntimeCorrelationRouting().Checksum()},
		{48, "production_runtime_acceptance_checksum", migrations.ProductionRuntimeAcceptance().Checksum()},
	} {
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_versions SET checksum=repeat('a',64) WHERE version=$1`, release.version); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key=$1`, release.key); err != nil {
			t.Fatal(err)
		}
		if version, err := database.SchemaVersion(ctx); err == nil {
			t.Fatalf("schema50 trusted changed predecessor%d: %s", release.version, version)
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_versions SET checksum=$2 WHERE version=$1`, release.version, release.checksum); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$2 WHERE key=$1`, release.key, release.checksum); err != nil {
			t.Fatal(err)
		}
	}
}
