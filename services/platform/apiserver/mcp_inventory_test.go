package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	mcpTestServerID = "pid_70000001-0000-4000-8000-000000000001"
	mcpTestToolID   = "pid_70000002-0000-4000-8000-000000000002"
	mcpTestAgentID  = "pid_10000001-0000-4000-8000-000000000001"
	mcpTestServer   = `{"id":"` + mcpTestServerID + `","name":"tracker","provider":"github","source_kind":"github_mcp_server","source":"repository_config","transport":"stdio","endpoint_host":null,"command":"npx","package":"@acme/tracker-mcp","package_pinned":false,"plain_http":false,"auth":"not_applicable","identity":"package:@acme/tracker-mcp","approval":"unapproved",` +
		`"tools":[{"id":"` + mcpTestToolID + `","name":"run_command","risk":"execute"}],"tool_count":1,"agents":[{"id":"` + mcpTestAgentID + `","name":"acme/alpha"}],"agent_count":1,"first_seen_at":"2026-08-19T01:00:00.000000Z","last_seen_at":"2026-08-19T02:00:00.000000Z"}`
)

// mcpJSONDatabase answers each statement with a fixed document. A registry
// put is answered with the audit id the statement was given, as the database
// function does.
type mcpJSONDatabase struct {
	inventoryJSONDatabase
	calls int
}

func (database *mcpJSONDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	database.calls++
	payload, err := database.inventoryJSONDatabase.QueryJSON(ctx, statement, arguments...)
	if audit, ok := "", statement == postgresMCPRegistryPutSQL && len(arguments) == 10; ok {
		audit, _ = arguments[8].(string)
		payload = bytes.Replace(payload, []byte("AUDIT"), []byte(audit), 1)
	}
	return payload, err
}

func mcpHandler(t *testing.T, responses map[string]json.RawMessage) (*inventoryHTTPHandler, *mcpJSONDatabase) {
	t.Helper()
	responses[postgresInventoryReadinessSQL] = json.RawMessage(`true`)
	database := &mcpJSONDatabase{inventoryJSONDatabase: inventoryJSONDatabase{schema: TypedInventorySchemaVersion, responses: responses}}
	repository, err := NewPostgresInventoryRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newInventoryHTTPHandler(repository, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	return handler, database
}

// GET /mcp-servers, GET /mcp-registry, PUT /mcp-registry and
// GET /agents/{id}/access through the handler and the repository: the
// statement each sends, and the exact body each answers with.
func TestMCPInventoryRoutesSendTheirStatementAndAnswerTheContract(t *testing.T) {
	entry := `{"identity":"package:@acme/tracker-mcp","status":"blocked","note":"unreviewed","version":2,"updated_by":"pid_50000001-0000-4000-8000-000000000001","updated_at":"2026-08-19T03:00:00.000000Z","server_count":1`
	access := `{"agent_id":"` + mcpTestAgentID + `","ai_actions":{"window_days":7,"granted":["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream"],"used":["bedrock:InvokeModel"],"unused":["bedrock:InvokeModelWithResponseStream"]},` +
		`"mcp_servers":[{"id":"` + mcpTestServerID + `","name":"tracker","identity":"package:@acme/tracker-mcp","approval":"blocked"}],"data_stores":[{"id":"pid_70000003-0000-4000-8000-000000000003","name":"All S3 buckets","service":"s3","access":"read","scope":"service"}],` +
		`"skills":[{"id":"pid_70000004-0000-4000-8000-000000000004","path":".claude/skills/release","kind":"skill"}]}`
	handler, database := mcpHandler(t, map[string]json.RawMessage{
		postgresMCPServerPageSQL:   json.RawMessage(`{"items":[` + mcpTestServer + `],"next_id":null}`),
		postgresMCPRegistryPageSQL: json.RawMessage(`{"items":[` + entry + `}]}`),
		postgresMCPRegistryPutSQL:  json.RawMessage(entry + `,"audit_id":"AUDIT"}`),
		postgresAgentAccessSQL:     json.RawMessage(access),
	})
	serve := func(request *http.Request) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	response := serve(inventoryRequest(t, "listMCPServers", "https://app.zasp.test/api/v1/mcp-servers?limit=50"))
	var page struct {
		Items    []json.RawMessage `json:"items"`
		PageInfo struct {
			HasMore bool `json:"has_more"`
		} `json:"page_info"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.PageInfo.HasMore || database.statement != postgresMCPServerPageSQL || len(database.arguments) != 5 || database.arguments[3] != "" || database.arguments[4] != 50 {
		t.Fatalf("servers: status=%d body=%s statement=%q args=%v", response.Code, response.Body.String(), database.statement, database.arguments)
	}
	var canonical, want any
	if json.Unmarshal(page.Items[0], &canonical) != nil || json.Unmarshal([]byte(strings.NewReplacer(".000000Z", "Z").Replace(mcpTestServer)), &want) != nil {
		t.Fatal("server is not JSON")
	}
	if got, expected := mustMarshalMCP(t, canonical), mustMarshalMCP(t, want); got != expected {
		t.Fatalf("server\n got %s\nwant %s", got, expected)
	}

	response = serve(inventoryRequest(t, "listMCPRegistry", "https://app.zasp.test/api/v1/mcp-registry"))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"identity":"package:@acme/tracker-mcp"`) || !strings.Contains(response.Body.String(), `"status":"blocked"`) || database.statement != postgresMCPRegistryPageSQL || len(database.arguments) != 3 {
		t.Fatalf("registry: status=%d body=%s", response.Code, response.Body.String())
	}

	// The put: the repository requires the saved entry to be the decision
	// that was asked for, with the audit id the handler generated.
	put := func(body string) *httptest.ResponseRecorder {
		request := inventoryRequest(t, "putMCPRegistryEntry", "https://app.zasp.test/api/v1/mcp-registry")
		request.Method = http.MethodPut
		request.Body = io.NopCloser(strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		return serve(request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, "pid_60000002-0000-4000-8000-000000000002")))
	}
	response = put(`{"identity":"package:@acme/tracker-mcp","status":"blocked","note":"unreviewed","expected_version":1}`)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` || !validProductID(response.Header().Get("X-Audit-ID")) || database.statement != postgresMCPRegistryPutSQL || len(database.arguments) != 10 ||
		database.arguments[3] != "pid_50000001-0000-4000-8000-000000000001" || database.arguments[4] != "package:@acme/tracker-mcp" || database.arguments[5] != "blocked" || database.arguments[7] != int64(1) || database.arguments[9] != "pid_60000002-0000-4000-8000-000000000002" {
		t.Fatalf("put: status=%d headers=%v body=%s args=%v", response.Code, response.Header(), response.Body.String(), database.arguments)
	}
	database.calls = 0
	for name, body := range map[string]string{
		"unknown status":     `{"identity":"package:@acme/tracker-mcp","status":"allowed","note":"","expected_version":0}`,
		"identity no prefix": `{"identity":"tracker","status":"approved","note":"","expected_version":0}`,
		"control character":  `{"identity":"host:a\nb","status":"approved","note":"","expected_version":0}`,
		"missing version":    `{"identity":"host:mcp.example.com","status":"approved","note":""}`,
		"unknown member":     `{"identity":"host:mcp.example.com","status":"approved","note":"","expected_version":0,"force":true}`,
		"negative version":   `{"identity":"host:mcp.example.com","status":"approved","note":"","expected_version":-1}`,
	} {
		if response := put(body); response.Code != http.StatusBadRequest || database.calls != 0 {
			t.Fatalf("%s: status=%d calls=%d", name, response.Code, database.calls)
		}
	}
	// A stale answer (another version than the one saved) is not passed on.
	database.responses[postgresMCPRegistryPutSQL] = json.RawMessage(strings.Replace(entry, `"version":2`, `"version":5`, 1) + `,"audit_id":"AUDIT"}`)
	if response := put(`{"identity":"package:@acme/tracker-mcp","status":"blocked","note":"unreviewed","expected_version":1}`); response.Code == http.StatusOK {
		t.Fatalf("an entry of another version was returned: %s", response.Body.String())
	}

	response = serve(inventoryRequest(t, "getAgentAccess", "https://app.zasp.test/api/v1/agents/"+mcpTestAgentID+"/access"))
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != access || database.statement != postgresAgentAccessSQL || len(database.arguments) != 4 || database.arguments[3] != mcpTestAgentID {
		t.Fatalf("access: status=%d body=%s", response.Code, response.Body.String())
	}
}

func mustMarshalMCP(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// A database answer outside the contract is refused, never passed on.
func TestMCPInventoryRefusesAnswersOutsideTheContract(t *testing.T) {
	for name, server := range map[string]string{
		"unknown approval":      strings.Replace(mcpTestServer, `"approval":"unapproved"`, `"approval":"trusted"`, 1),
		"unknown risk":          strings.Replace(mcpTestServer, `"risk":"execute"`, `"risk":"dangerous"`, 1),
		"package without pin":   strings.Replace(mcpTestServer, `"package_pinned":false`, `"package_pinned":null`, 1),
		"extra member":          strings.Replace(mcpTestServer, `"plain_http":false`, `"plain_http":false,"env":{"TOKEN":"x"}`, 1),
		"count below the list":  strings.Replace(mcpTestServer, `"tool_count":1`, `"tool_count":0`, 1),
		"identity not a prefix": strings.Replace(mcpTestServer, `"identity":"package:@acme/tracker-mcp"`, `"identity":"tracker"`, 1),
	} {
		handler, _ := mcpHandler(t, map[string]json.RawMessage{postgresMCPServerPageSQL: json.RawMessage(`{"items":[` + server + `],"next_id":null}`)})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, inventoryRequest(t, "listMCPServers", "https://app.zasp.test/api/v1/mcp-servers"))
		if response.Code == http.StatusOK {
			t.Fatalf("%s: answered %s", name, response.Body.String())
		}
	}
}

// The API reaches the MCP statements only as the operations that own them,
// in the caller's scope, as the caller, on a target the proof allows.
func TestMCPStatementsAreBoundToTheirOperations(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	organization, workspace, environment, principal := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	allowed := []AuthorizationTarget{{Scope: identity.Scope, Kind: "environment", ID: environment}, {Scope: identity.Scope, Kind: "agent", ID: mcpTestAgentID}}
	grant := func(operation string) RequestAuthorization {
		return RequestAuthorization{Identity: identity, OperationID: operation, Allowed: allowed, PathParameters: map[string]string{"id": mcpTestAgentID}}
	}
	put := []any{organization, workspace, environment, principal, "host:mcp.example.com", "approved", "", int64(0), "pid_60000001-0000-4000-8000-000000000001", "pid_60000002-0000-4000-8000-000000000002"}
	for _, test := range []struct {
		name      string
		grant     RequestAuthorization
		statement string
		arguments []any
		want      bool
	}{
		{"servers", grant("listMCPServers"), postgresMCPServerPageSQL, []any{organization, workspace, environment, "", 50}, true},
		{"servers as another operation", grant("listTools"), postgresMCPServerPageSQL, []any{organization, workspace, environment, "", 50}, false},
		{"servers of another scope", grant("listMCPServers"), postgresMCPServerPageSQL, []any{organization, workspace, "pid_10000009-0000-4000-8000-000000000009", "", 50}, false},
		{"registry", grant("listMCPRegistry"), postgresMCPRegistryPageSQL, []any{organization, workspace, environment}, true},
		{"registry put", grant("putMCPRegistryEntry"), postgresMCPRegistryPutSQL, put, true},
		{"registry put as a read", grant("listMCPRegistry"), postgresMCPRegistryPutSQL, put, false},
		{"registry put as another principal", grant("putMCPRegistryEntry"), postgresMCPRegistryPutSQL, append(append([]any{}, put[:3]...), append([]any{"pid_10000008-0000-4000-8000-000000000008"}, put[4:]...)...), false},
		{"access", grant("getAgentAccess"), postgresAgentAccessSQL, []any{organization, workspace, environment, mcpTestAgentID}, true},
		{"access of an agent the proof does not allow", grant("getAgentAccess"), postgresAgentAccessSQL, []any{organization, workspace, environment, "pid_10000007-0000-4000-8000-000000000007"}, false},
	} {
		if got := authorizationStatementAllowed(test.grant, test.statement, test.arguments); got != test.want {
			t.Errorf("%s: allowed = %t", test.name, got)
		}
	}
}
