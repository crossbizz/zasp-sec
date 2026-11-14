package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/hostedgateway"
)

const (
	gatewayTestServerID = "pid_61000001-0000-4000-8000-000000000001"
	gatewayTestRecordID = "pid_61000002-0000-4000-8000-000000000002"
)

// gatewayTxFixture answers each statement with the payload the test gave
// for it, and keeps what reached it.
type gatewayTxFixture struct {
	pgx.Tx
	mu         sync.Mutex
	payloads   map[string]string
	statements []string
	arguments  [][]any
	fences     int
}

func (f *gatewayTxFixture) Exec(_ context.Context, statement string, _ ...any) (pgconn.CommandTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if statement == `SELECT zasp_authorization80.fence($1::text)` {
		f.fences++
	}
	return pgconn.CommandTag{}, nil
}

func (f *gatewayTxFixture) QueryRow(_ context.Context, statement string, arguments ...any) pgx.Row {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statements = append(f.statements, statement)
	f.arguments = append(f.arguments, arguments)
	return completionRowFixture{payload: []byte(f.payloads[statement])}
}
func (f *gatewayTxFixture) Commit(context.Context) error   { return nil }
func (f *gatewayTxFixture) Rollback(context.Context) error { return nil }

func (f *gatewayTxFixture) seen() ([]string, [][]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.statements...), append([][]any(nil), f.arguments...)
}

type gatewayDriverFixture struct{ tx *gatewayTxFixture }

func (f *gatewayDriverFixture) Begin(context.Context) (pgx.Tx, error) { return f.tx, nil }
func (f *gatewayDriverFixture) QueryRow(context.Context, string, ...any) PostgresRow {
	return completionRowFixture{ready: true}
}
func (f *gatewayDriverFixture) Exec(context.Context, string, ...any) error { return nil }
func (f *gatewayDriverFixture) Close() error                               { return nil }

type gatewayFixture struct {
	secondary *secondaryFixture
	tx        *gatewayTxFixture
	database  *PostgresJSONDatabase
	handler   *hostedGatewayHandler
}

func newGatewayFixture(t *testing.T, kind CredentialKind, permissions ...string) *gatewayFixture {
	t.Helper()
	f := newSecondaryFixture(t)
	f.identity.CredentialKind, f.credential.Kind = kind, kind
	if kind == CredentialBearerToken {
		f.credential.PATCeiling = permissions
	}
	f.identity.credentialBinding = f.credential
	tx := &gatewayTxFixture{payloads: map[string]string{}}
	database, err := NewPostgresJSONDatabase(&gatewayDriverFixture{tx: tx})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	return &gatewayFixture{secondary: f, tx: tx, database: database, handler: &hostedGatewayHandler{database: database, newProductID: func() (string, error) { return gatewayTestRecordID, nil }}}
}

func (f *gatewayFixture) serve(t *testing.T, routed RoutedOperation, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	if routed.PathParameters == nil {
		routed.PathParameters = map[string]string{}
	}
	ctx := context.WithValue(f.secondary.request(t, routed), identityContextKey{}, f.secondary.identity)
	request := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request, routed)
	return recorder
}

const gatewayPolicyPayload = `{"environment_id":"%s","unapproved_servers":"refuse","denied_tool_risks":["execute"],"requests_per_minute":120,"version":%d,"updated_at":"2026-11-14T10:00:00.000000Z"%s}`

func gatewayServerPayload(version int, extra string) string {
	return fmt.Sprintf(`{"id":"%s","name":"Tickets","upstream_url":"https://mcp.tickets.test/mcp","upstream_host":"mcp.tickets.test","identity":"host:mcp.tickets.test","approval":"approved","enabled":true,
"allowed_tools":[],"denied_tools":["delete_ticket"],"tools":[{"name":"run_report","risk":"execute","last_seen_at":"2026-11-14T10:00:00.000000Z"}],"tool_count":1,"last_activity_at":null,
"version":%d,"created_at":"2026-11-14T09:00:00.000000Z","updated_at":"2026-11-14T10:00:00.000000Z"%s}`, gatewayTestServerID, version, extra)
}

func TestHostedGatewayPolicyReadAndWrite(t *testing.T) {
	f := newGatewayFixture(t, CredentialBrowserSession)
	environment := f.secondary.identity.Scope.EnvironmentID().String()
	f.tx.payloads[currentGatewayPolicySQL] = fmt.Sprintf(gatewayPolicyPayload, environment, 3, "")
	response := f.serve(t, RoutedOperation{OperationID: "getGatewayPolicy"}, http.MethodGet, "/api/v1/gateway/policy", "", nil)
	var policy GatewayPolicy
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"3"` || response.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(response.Body.Bytes(), &policy) != nil ||
		!exactJSONFields(response.Body.Bytes(), "denied_tool_risks", "environment_id", "gateway_enabled", "requests_per_minute", "unapproved_servers", "updated_at", "version") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	// This deployment does not host the traffic routes, and says so.
	if policy.UnapprovedServers != "refuse" || len(policy.DeniedToolRisks) != 1 || policy.RequestsPerMinute != 120 || policy.GatewayEnabled {
		t.Fatalf("policy=%+v", policy)
	}
	const audit = `,"audit_id":"` + gatewayTestRecordID + `","correlation_id":"pid_ffffffff-ffff-4fff-8fff-ffffffffffff"`
	f.tx.payloads[currentGatewaySetPolicySQL] = fmt.Sprintf(gatewayPolicyPayload, environment, 4, audit)
	headers := map[string]string{"If-Match": `"3"`, "Idempotency-Key": "gateway-policy-0001"}
	response = f.serve(t, RoutedOperation{OperationID: "putGatewayPolicy"}, http.MethodPut, "/api/v1/gateway/policy", `{"unapproved_servers":"refuse","denied_tool_risks":["execute"],"requests_per_minute":120}`, headers)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"4"` || response.Header().Get("X-Audit-ID") != gatewayTestRecordID {
		t.Fatalf("status=%d body=%s headers=%v", response.Code, response.Body.String(), response.Header())
	}
	statements, arguments := f.tx.seen()
	if len(statements) != 2 || statements[1] != currentGatewaySetPolicySQL || arguments[1][5].(int64) != 3 || string(arguments[1][4].(json.RawMessage)) != `{"denied_tool_risks":["execute"],"requests_per_minute":120,"unapproved_servers":"refuse"}` {
		t.Fatalf("statements=%v arguments=%v", statements, arguments)
	}
	for name, body := range map[string]string{
		"an unknown risk class": `{"unapproved_servers":"refuse","denied_tool_risks":["dangerous"],"requests_per_minute":120}`,
		"a risk class twice":    `{"unapproved_servers":"refuse","denied_tool_risks":["read","read"],"requests_per_minute":120}`,
		"an unknown choice":     `{"unapproved_servers":"maybe","denied_tool_risks":[],"requests_per_minute":120}`,
		"a negative rate":       `{"unapproved_servers":"allow","denied_tool_risks":[],"requests_per_minute":-1}`,
		"a missing member":      `{"unapproved_servers":"allow","denied_tool_risks":[]}`,
		"an unknown member":     `{"unapproved_servers":"allow","denied_tool_risks":[],"requests_per_minute":1,"note":"x"}`,
	} {
		if response = f.serve(t, RoutedOperation{OperationID: "putGatewayPolicy"}, http.MethodPut, "/api/v1/gateway/policy", body, headers); response.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d", name, response.Code)
		}
	}
	if response = f.serve(t, RoutedOperation{OperationID: "putGatewayPolicy"}, http.MethodPut, "/api/v1/gateway/policy", `{"unapproved_servers":"allow","denied_tool_risks":[],"requests_per_minute":1}`, map[string]string{"Idempotency-Key": "gateway-policy-0002"}); response.Code != http.StatusBadRequest {
		t.Fatalf("a write without If-Match: status=%d", response.Code)
	}
	if statements, _ = f.tx.seen(); len(statements) != 2 {
		t.Fatalf("a refused request reached the database: %v", statements)
	}
}

func TestHostedGatewayServersAndActivity(t *testing.T) {
	f := newGatewayFixture(t, CredentialBrowserSession)
	f.tx.payloads[currentGatewayServerPageSQL] = `{"items":[` + gatewayServerPayload(2, "") + `]}`
	response := f.serve(t, RoutedOperation{OperationID: "listMCPGatewayServers"}, http.MethodGet, "/api/v1/gateway/mcp-servers", "", nil)
	var list struct {
		Items          []MCPGatewayServer `json:"items"`
		GatewayEnabled bool               `json:"gateway_enabled"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &list) != nil || len(list.Items) != 1 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	// The address an agent's configuration names is the server's path under
	// this API.
	if server := list.Items[0]; server.GatewayPath != "/api/v1/gateway/mcp/"+gatewayTestServerID || server.Identity != "host:mcp.tickets.test" || server.Approval != "approved" || server.Tools[0].Risk != "execute" || list.GatewayEnabled {
		t.Fatalf("server=%+v", list.Items[0])
	}

	const audit = `,"audit_id":"` + gatewayTestRecordID + `","correlation_id":"pid_ffffffff-ffff-4fff-8fff-ffffffffffff"`
	put := RoutedOperation{OperationID: "putMCPGatewayServer", PathParameters: map[string]string{"id": gatewayTestServerID}}
	path := "/api/v1/gateway/mcp-servers/" + gatewayTestServerID
	const body = `{"name":"Tickets","upstream_url":"https://mcp.tickets.test/mcp","enabled":true,"allowed_tools":[],"denied_tools":["delete_ticket"]}`
	f.tx.payloads[currentGatewayServerPutSQL] = gatewayServerPayload(1, audit)
	response = f.serve(t, put, http.MethodPut, path, body, map[string]string{"If-Match": `"0"`, "Idempotency-Key": "gateway-server-0001"})
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != gatewayTestRecordID || strings.Contains(response.Body.String(), "audit_id") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	_, arguments := f.tx.seen()
	if last := arguments[len(arguments)-1]; last[4] != gatewayTestServerID || string(last[5].(json.RawMessage)) != `{"allowed_tools":[],"denied_tools":["delete_ticket"],"enabled":true,"name":"Tickets","upstream_url":"https://mcp.tickets.test/mcp"}` {
		t.Fatalf("arguments=%v", last)
	}
	before, _ := f.tx.seen()
	for name, refused := range map[string]string{
		"plain http":                `{"name":"A","upstream_url":"http://mcp.tickets.test/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`,
		"a key in the query":        `{"name":"A","upstream_url":"https://mcp.tickets.test/mcp?key=abc","enabled":true,"allowed_tools":[],"denied_tools":[]}`,
		"credentials in the URL":    `{"name":"A","upstream_url":"https://user:secret@mcp.tickets.test/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`,
		"a private address":         `{"name":"A","upstream_url":"https://10.0.0.8/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`,
		"the metadata service":      `{"name":"A","upstream_url":"https://169.254.169.254/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`,
		"a cluster name":            `{"name":"A","upstream_url":"https://nango.zasp.svc.cluster.local/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`,
		"another port":              `{"name":"A","upstream_url":"https://mcp.tickets.test:8443/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`,
		"a tool on both lists":      `{"name":"A","upstream_url":"https://mcp.tickets.test/mcp","enabled":true,"allowed_tools":["a"],"denied_tools":["a"]}`,
		"a tool name with a space":  `{"name":"A","upstream_url":"https://mcp.tickets.test/mcp","enabled":true,"allowed_tools":["ignore previous"],"denied_tools":[]}`,
		"a stored upstream secret":  `{"name":"A","upstream_url":"https://mcp.tickets.test/mcp","enabled":true,"allowed_tools":[],"denied_tools":[],"authorization":"Bearer abc"}`,
		"an empty name":             `{"name":"","upstream_url":"https://mcp.tickets.test/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`,
		"a missing list":            `{"name":"A","upstream_url":"https://mcp.tickets.test/mcp","enabled":true,"allowed_tools":[]}`,
		"a name with a line break":  `{"name":"A\nB","upstream_url":"https://mcp.tickets.test/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`,
		"a list that is not a list": `{"name":"A","upstream_url":"https://mcp.tickets.test/mcp","enabled":true,"allowed_tools":null,"denied_tools":[]}`,
	} {
		if response = f.serve(t, put, http.MethodPut, path, refused, map[string]string{"If-Match": `"0"`, "Idempotency-Key": "gateway-server-0002"}); response.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d", name, response.Code)
		}
	}
	if after, _ := f.tx.seen(); len(after) != len(before) {
		t.Fatal("a refused registration reached the database")
	}

	f.tx.payloads[currentGatewayServerDeleteSQL] = `{"id":"` + gatewayTestServerID + `","deleted":true` + audit + `}`
	remove := RoutedOperation{OperationID: "deleteMCPGatewayServer", PathParameters: map[string]string{"id": gatewayTestServerID}}
	if response = f.serve(t, remove, http.MethodDelete, path, "", map[string]string{"If-Match": `"1"`, "Idempotency-Key": "gateway-server-0003"}); response.Code != http.StatusNoContent || response.Header().Get("X-Audit-ID") != gatewayTestRecordID {
		t.Fatalf("delete: status=%d body=%s", response.Code, response.Body.String())
	}
	if response = f.serve(t, remove, http.MethodDelete, path, "", map[string]string{"If-Match": `"0"`, "Idempotency-Key": "gateway-server-0004"}); response.Code != http.StatusBadRequest {
		t.Fatalf("delete without a version: status=%d", response.Code)
	}

	principal := f.secondary.identity.PrincipalID.String()
	f.tx.payloads[currentGatewayActivitySQL] = `{"items":[{"id":"` + gatewayTestRecordID + `","created_at":"2026-11-14T10:00:00.000000Z","surface":"mcp","operation":"tools/call","direction":"response","decision":"block","reason":"guardrail",
"rules":[{"id":"injection.instruction_override","category":"prompt_injection","mode":"block","count":1}],"bytes":412,"content_digest":"sha256:` + strings.Repeat("ab", 32) + `","server_id":"` + gatewayTestServerID + `","server_name":"Tickets",
"tool_name":"read_page","provider":null,"model":null,"agent_id":"support-agent","principal_id":"` + principal + `"}],"next_id":"` + gatewayTestRecordID + `"}`
	response = f.serve(t, RoutedOperation{OperationID: "listGatewayActivity"}, http.MethodGet, "/api/v1/gateway/activity?surface=mcp&decision=block&server_id="+gatewayTestServerID+"&agent_id=support-agent&limit=1", "", nil)
	var page struct {
		Items      []GatewayDecision `json:"items"`
		NextCursor *string           `json:"next_cursor"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.NextCursor == nil || *page.NextCursor != gatewayTestRecordID || page.Items[0].Reason != "guardrail" || *page.Items[0].ToolName != "read_page" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	_, arguments = f.tx.seen()
	if last := arguments[len(arguments)-1]; len(last) != 9 || last[3] != "mcp" || last[4] != gatewayTestServerID || last[5] != "support-agent" || last[6] != "block" || last[7] != "" || last[8] != 1 {
		t.Fatalf("arguments=%v", last)
	}
	for _, query := range []string{"?surface=web", "?decision=maybe", "?limit=0", "?limit=101", "?limit=1e1", "?server_id=x", "?before=x", "?agent_id=a%20b", "?surface=mcp&surface=llm", "?text=hello"} {
		if response = f.serve(t, RoutedOperation{OperationID: "listGatewayActivity"}, http.MethodGet, "/api/v1/gateway/activity"+query, "", nil); response.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d", query, response.Code)
		}
	}
}

// The statement gate: each statement belongs to its own operation, scope and
// credential, and a record has a closed shape.
func TestHostedGatewayStatementGate(t *testing.T) {
	token := newGatewayFixture(t, CredentialBearerToken, PermissionUseGateway, "view", "manage_workflows")
	browser := newGatewayFixture(t, CredentialBrowserSession)
	o, w, e := gatewayScope(token.secondary.identity)
	actor := token.secondary.identity.PrincipalID.String()
	grant := func(f *gatewayFixture, routed RoutedOperation) RequestAuthorization {
		if routed.PathParameters == nil {
			routed.PathParameters = map[string]string{}
		}
		value, _ := requestAuthorizationFromContext(f.secondary.request(t, routed))
		return value
	}
	call := RoutedOperation{OperationID: "callMCPGateway", PathParameters: map[string]string{"id": gatewayTestServerID}}
	chat := RoutedOperation{OperationID: "createGatewayChatCompletion"}
	record := func(text string) json.RawMessage {
		return json.RawMessage(`{"records":[{"id":"` + gatewayTestRecordID + `","surface":"mcp","operation":"tools/call","direction":"request","decision":"allow","reason":"none","rules":[],"bytes":10,"content_digest":"sha256:` + strings.Repeat("ab", 32) + `","tool_name":"lookup","provider":null,"model":null,"agent_id":null` + text + `}],"tools":[]}`)
	}
	for name, test := range map[string]struct {
		grant     RequestAuthorization
		statement string
		arguments []any
		allowed   bool
	}{
		"open for an MCP call":             {grant(token, call), currentGatewayOpenSQL, []any{o, w, e, actor, "callMCPGateway", gatewayTestServerID}, true},
		"open for a chat completion":       {grant(token, chat), currentGatewayOpenSQL, []any{o, w, e, actor, "createGatewayChatCompletion", ""}, true},
		"record of an MCP call":            {grant(token, call), currentGatewayRecordSQL, []any{o, w, e, actor, "callMCPGateway", gatewayTestServerID, record("")}, true},
		"open of another server":           {grant(token, call), currentGatewayOpenSQL, []any{o, w, e, actor, "callMCPGateway", gatewayTestRecordID}, false},
		"open that names another route":    {grant(token, call), currentGatewayOpenSQL, []any{o, w, e, actor, "createGatewayMessage", gatewayTestServerID}, false},
		"a server for a model request":     {grant(token, chat), currentGatewayOpenSQL, []any{o, w, e, actor, "createGatewayChatCompletion", gatewayTestServerID}, false},
		"open without a server":            {grant(token, call), currentGatewayOpenSQL, []any{o, w, e, actor, "callMCPGateway", ""}, false},
		"open in another Environment":      {grant(token, call), currentGatewayOpenSQL, []any{o, w, gatewayTestRecordID, actor, "callMCPGateway", gatewayTestServerID}, false},
		"open as another principal":        {grant(token, call), currentGatewayOpenSQL, []any{o, w, e, gatewayTestRecordID, "callMCPGateway", gatewayTestServerID}, false},
		"open under a policy read":         {grant(token, RoutedOperation{OperationID: "getGatewayPolicy"}), currentGatewayOpenSQL, []any{o, w, e, actor, "callMCPGateway", gatewayTestServerID}, false},
		"a record with a text member":      {grant(token, call), currentGatewayRecordSQL, []any{o, w, e, actor, "callMCPGateway", gatewayTestServerID, record(`,"text":"the customer's question"`)}, false},
		"a record that is not JSON":        {grant(token, call), currentGatewayRecordSQL, []any{o, w, e, actor, "callMCPGateway", gatewayTestServerID, "records"}, false},
		"the policy under a traffic grant": {grant(token, call), currentGatewayPolicySQL, []any{o, w, e}, false},
		"activity under a traffic grant":   {grant(token, chat), currentGatewayActivitySQL, []any{o, w, e, "", "", "", "", "", 50}, false},
		"a guardrail decision's statement": {grant(token, chat), currentGuardrailDecideSQL, []any{o, w, e, actor, json.RawMessage(`{}`)}, false},
		"the policy for a browser":         {grant(browser, RoutedOperation{OperationID: "getGatewayPolicy"}), currentGatewayPolicySQL, []any{o, w, e}, true},
		"a server change for its path":     {grant(browser, RoutedOperation{OperationID: "putMCPGatewayServer", PathParameters: map[string]string{"id": gatewayTestServerID}}), currentGatewayServerPutSQL, []any{o, w, e, actor, gatewayTestServerID, json.RawMessage(`{}`), int64(0), gatewayTestRecordID, gatewayTestRecordID}, true},
		"a server change of another":       {grant(browser, RoutedOperation{OperationID: "putMCPGatewayServer", PathParameters: map[string]string{"id": gatewayTestServerID}}), currentGatewayServerPutSQL, []any{o, w, e, actor, gatewayTestRecordID, json.RawMessage(`{}`), int64(0), gatewayTestRecordID, gatewayTestRecordID}, false},
		"a removal under a change":         {grant(browser, RoutedOperation{OperationID: "putMCPGatewayServer", PathParameters: map[string]string{"id": gatewayTestServerID}}), currentGatewayServerDeleteSQL, []any{o, w, e, actor, gatewayTestServerID, int64(1), gatewayTestRecordID, gatewayTestRecordID}, false},
	} {
		if got := authorizationStatementAllowed(test.grant, test.statement, test.arguments); got != test.allowed {
			t.Errorf("%s: allowed=%v, want %v", name, got, test.allowed)
		}
	}
	// A browser session never holds a traffic grant; were one forged, the
	// gate refuses it again.
	forged := grant(token, call)
	forged.Identity.CredentialKind, forged.Credential.Kind = CredentialBrowserSession, CredentialBrowserSession
	if authorizationStatementAllowed(forged, currentGatewayOpenSQL, []any{o, w, e, actor, "callMCPGateway", gatewayTestServerID}) {
		t.Error("a browser session was admitted to the gateway's traffic")
	}
}

// The traffic routes need a token that holds use_gateway: not a browser
// session, and not a token that can only read.
func TestHostedGatewayTrafficNeedsItsOwnPermission(t *testing.T) {
	call := RoutedOperation{OperationID: "callMCPGateway", PathParameters: map[string]string{"id": gatewayTestServerID}}
	for name, test := range map[string]struct {
		fixture *gatewayFixture
		allowed bool
	}{
		"a gateway token":               {newGatewayFixture(t, CredentialBearerToken, PermissionUseGateway), true},
		"a reading token":               {newGatewayFixture(t, CredentialBearerToken, "view"), false},
		"a guardrail decision token":    {newGatewayFixture(t, CredentialBearerToken, PermissionDecideGuardrails), false},
		"an administrator's session":    {newGatewayFixture(t, CredentialBrowserSession), false},
		"a token with every other one":  {newGatewayFixture(t, CredentialBearerToken, "view", "manage_workflows", "manage_findings", "run_tests"), false},
		"a gateway and a reading token": {newGatewayFixture(t, CredentialBearerToken, PermissionUseGateway, "view"), true},
	} {
		f := test.fixture.secondary
		for _, operation := range []RoutedOperation{call, {OperationID: "closeMCPGatewaySession", PathParameters: call.PathParameters}, {OperationID: "createGatewayChatCompletion"}, {OperationID: "createGatewayResponse"}, {OperationID: "createGatewayMessage"}} {
			_, err := f.authorizer.Authorize(context.Background(), f.identity, f.credential, operation)
			if (err == nil) != test.allowed {
				t.Errorf("%s, %s: err=%v, want allowed=%v", name, operation.OperationID, err, test.allowed)
			}
		}
	}
	// A gateway token alone reads nothing.
	f := newGatewayFixture(t, CredentialBearerToken, PermissionUseGateway).secondary
	for _, operation := range []string{"getGatewayPolicy", "listMCPGatewayServers", "listGatewayActivity", "listAgents", "listFindings", "getGuardrailPolicy", "putGatewayPolicy"} {
		if _, err := f.authorizer.Authorize(context.Background(), f.identity, f.credential, RoutedOperation{OperationID: operation, PathParameters: map[string]string{}}); err == nil {
			t.Errorf("a gateway token was admitted to %s", operation)
		}
	}
	if !validPermissions([]string{PermissionUseGateway}) || !validPermissions([]string{"view", PermissionUseGateway, PermissionDecideGuardrails}) {
		t.Error("use_gateway is not a permission an identity may carry")
	}
}

// One tool call through the composed handler: the policy is read with one
// statement, the decisions are written with another, and nothing of the
// arguments or the result reaches the database.
func TestHostedGatewayTrafficThroughTheHandler(t *testing.T) {
	var upstreamRequests []map[string]any
	var upstreamAuthorization []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		var message map[string]any
		_ = json.Unmarshal(raw, &message)
		upstreamRequests = append(upstreamRequests, message)
		upstreamAuthorization = append(upstreamAuthorization, request.Header.Get("Authorization"))
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"jsonrpc": "2.0", "id": message["id"], "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "The customer is jane.customer@example.com."}}, "isError": false}})
	}))
	defer upstream.Close()
	f := newGatewayFixture(t, CredentialBearerToken, PermissionUseGateway)
	routed := RoutedOperation{OperationID: "callMCPGateway", PathParameters: map[string]string{"id": gatewayTestServerID}}
	path := "/api/v1/gateway/mcp/" + gatewayTestServerID
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_customer","arguments":{"query":"the account of private.person@example.com"}}}`
	headers := map[string]string{hostedgateway.HeaderUpstreamAuthorization: "Bearer upstream-credential", hostedgateway.HeaderAgentID: "support-agent"}

	// Where the deployment does not host the gateway the route is absent.
	if response := f.serve(t, routed, http.MethodPost, path, body, headers); response.Code != http.StatusNotFound {
		t.Fatalf("a deployment without the gateway served its traffic: %d", response.Code)
	}
	gateway, err := NewHostedGateway(HostedGatewayConfig{Timeout: 20 * time.Second, AllowUpstreamURL: func(value string) bool { return strings.HasPrefix(value, upstream.URL) },
		Upstream: hostedgateway.UpstreamConfig{AllowAddress: func(address net.IP) bool { return address.IsLoopback() }, RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}})
	if err != nil {
		t.Fatal(err)
	}
	f.handler.gateway = gateway
	f.tx.payloads[currentGatewayOpenSQL] = `{"policy":{"version":2,"unapproved_servers":"refuse","denied_tool_risks":["execute"],"requests_per_minute":600},"guardrail":{"version":5,"rules":{"pii.phone":"monitor"}},
"server":{"id":"` + gatewayTestServerID + `","name":"Tickets","upstream_url":"` + upstream.URL + `/mcp","enabled":true,"allowed_tools":[],"denied_tools":[],"approval":"approved"}}`
	f.tx.payloads[currentGatewayRecordSQL] = `{"recorded":2}`
	response := f.serve(t, routed, http.MethodPost, path, body, headers)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "The customer is [REDACTED:pii.email].") || strings.Contains(response.Body.String(), "jane.customer") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(upstreamRequests) != 1 || upstreamAuthorization[0] != "Bearer upstream-credential" || upstreamRequests[0]["params"].(map[string]any)["arguments"].(map[string]any)["query"] != "the account of [REDACTED:pii.email]" {
		t.Fatalf("upstream: %v %v", upstreamRequests, upstreamAuthorization)
	}
	statements, arguments := f.tx.seen()
	if len(statements) != 2 || statements[0] != currentGatewayOpenSQL || statements[1] != currentGatewayRecordSQL || f.tx.fences != 2 {
		t.Fatalf("statements=%v fences=%d", statements, f.tx.fences)
	}
	if open := arguments[0]; len(open) != 6 || open[4] != "callMCPGateway" || open[5] != gatewayTestServerID {
		t.Fatalf("open arguments=%v", open)
	}
	raw := arguments[1][6].(json.RawMessage)
	var batch gatewayRecordBatch
	if !exactJSONFields(raw, "records", "tools") || json.Unmarshal(raw, &batch) != nil || len(batch.Records) != 2 || len(batch.Tools) != 0 {
		t.Fatalf("record=%s", raw)
	}
	for index, record := range batch.Records {
		var members map[string]json.RawMessage
		encoded, _ := json.Marshal(record)
		_ = json.Unmarshal(encoded, &members)
		if len(members) != 13 || record.Surface != "mcp" || record.Operation != "tools/call" || record.Decision != "redact" || record.Reason != "guardrail" || *record.ToolName != "lookup_customer" || *record.AgentID != "support-agent" ||
			record.Provider != nil || record.Model != nil || record.Direction != []string{"request", "response"}[index] || len(record.Rules) != 1 || record.Rules[0].ID != "pii.email" || len(record.ContentDigest) != 71 {
			t.Fatalf("record %d: %s", index, encoded)
		}
	}
	// Nothing of the argument or of the result is in any statement.
	for _, statement := range arguments {
		for _, argument := range statement {
			rendered := fmt.Sprint(argument)
			if value, ok := argument.(json.RawMessage); ok {
				rendered = string(value)
			}
			for _, fragment := range []string{"private.person", "jane.customer", "The customer", "the account of", "upstream-credential"} {
				if strings.Contains(rendered, fragment) {
					t.Fatalf("a statement argument holds %q: %s", fragment, rendered)
				}
			}
		}
	}
	// A request that is not a JSON body of an API token is refused before
	// anything is read.
	before, _ := f.tx.seen()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body))).WithContext(context.WithValue(f.secondary.request(t, routed), identityContextKey{}, f.secondary.identity))
	request.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request, routed)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("a text body: %d", recorder.Code)
	}
	if after, _ := f.tx.seen(); len(after) != len(before) {
		t.Fatal("a refused request reached the database")
	}
}

// A record written after the request's proof has aged is written under a
// fresh decision of the same authorizer, for the same token and operation.
func TestHostedGatewayLateRecordIsAuthorizedAgain(t *testing.T) {
	f := newGatewayFixture(t, CredentialBearerToken, PermissionUseGateway)
	routed := RoutedOperation{OperationID: "createGatewayChatCompletion", PathParameters: map[string]string{}}
	ctx := f.secondary.request(t, routed)
	first, _ := requestAuthorizationFromContext(ctx)
	store := &gatewayRequestStore{handler: f.handler, identity: f.secondary.identity, route: routed, issued: time.Now()}
	if same, _ := requestAuthorizationFromContext(store.current(ctx)); string(same.attestation) != string(first.attestation) || len(f.secondary.resolved) != 1 {
		t.Fatal("a fresh proof was replaced")
	}
	store.issued = time.Now().Add(-gatewayProofAge - time.Second)
	renewed, _ := requestAuthorizationFromContext(store.current(context.WithoutCancel(ctx)))
	if string(renewed.attestation) == string(first.attestation) || renewed.OperationID != "createGatewayChatCompletion" || len(f.secondary.resolved) != 2 {
		t.Fatalf("the aged proof was not replaced: resolved=%v", f.secondary.resolved)
	}
	// The renewed proof is kept for the statements that follow.
	if again, _ := requestAuthorizationFromContext(store.current(ctx)); string(again.attestation) != string(renewed.attestation) || len(f.secondary.resolved) != 2 {
		t.Fatal("the renewed proof was not reused")
	}
	f.tx.payloads[currentGatewayRecordSQL] = `{"recorded":1}`
	store.issued = time.Now().Add(-gatewayProofAge - time.Second)
	err := store.Record(context.WithoutCancel(ctx), "", []hostedgateway.Record{{Surface: "llm", Operation: "chat.completions", Direction: "response", Decision: "allow", Reason: "none", Bytes: 12, Digest: "sha256:" + strings.Repeat("cd", 32), Provider: "openai", Model: "gpt-test"}}, nil)
	if statements, _ := f.tx.seen(); err != nil || len(statements) != 1 || len(f.secondary.resolved) != 3 {
		t.Fatalf("late record: err=%v resolved=%v", err, f.secondary.resolved)
	}
}

// The gateway's traffic routes take a body larger than the product API's;
// every other route keeps its limit.
func TestProductMiddlewareGatewayBodyLimit(t *testing.T) {
	reached := map[string]int{}
	handler, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://app.example.test", MaximumBodyBytes: 1024, GatewayMaximumBodyBytes: 64 * 1024,
		Authenticate: func(context.Context, Credential) (RequestIdentity, error) { return fixtureRequestIdentity(t), nil }, GenerateCorrelationID: func() string { return "pid_ffffffff-ffff-4fff-8fff-ffffffffffff" }},
		http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			body, _ := io.ReadAll(request.Body)
			reached[request.URL.Path] = len(body)
		}))
	if err != nil {
		t.Fatal(err)
	}
	large := `{"messages":"` + strings.Repeat("a", 30*1024) + `"}`
	for path, want := range map[string]int{
		"/api/v1/gateway/llm/v1/chat/completions":            http.StatusOK,
		"/api/v1/gateway/mcp/" + gatewayTestServerID:         http.StatusOK,
		"/api/v1/gateway/policy":                             http.StatusRequestEntityTooLarge,
		"/api/v1/gateway/mcp-servers/" + gatewayTestServerID: http.StatusRequestEntityTooLarge,
		"/api/v1/guardrails/decisions":                       http.StatusRequestEntityTooLarge,
		"/api/v1/gateway/llm":                                http.StatusRequestEntityTooLarge,
	} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(large))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer token-of-the-test")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != want || (want == http.StatusOK) != (reached[path] == len(large)) {
			t.Errorf("%s: status=%d reached=%d", path, recorder.Code, reached[path])
		}
	}
	// A caller of the gateway may name the character set of its JSON; a
	// caller of the product API may not.
	for path, want := range map[string]int{"/api/v1/gateway/llm/v1/messages": http.StatusOK, "/api/v1/gateway/policy": http.StatusUnsupportedMediaType} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"a":1}`))
		request.Header.Set("Content-Type", "application/json; charset=UTF-8")
		request.Header.Set("Authorization", "Bearer token-of-the-test")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != want {
			t.Errorf("%s with a charset: status=%d", path, recorder.Code)
		}
	}
	for _, contentType := range []string{"text/plain", "application/json; charset=latin1", "application/x-www-form-urlencoded"} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/llm/v1/messages", strings.NewReader(`{"a":1}`))
		request.Header.Set("Content-Type", contentType)
		request.Header.Set("Authorization", "Bearer token-of-the-test")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%s on a gateway route: status=%d", contentType, recorder.Code)
		}
	}
	// And the gateway's own limit holds.
	request := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/llm/v1/messages", strings.NewReader(`{"messages":"`+strings.Repeat("a", 70*1024)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer token-of-the-test")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body over the gateway's limit: %d", recorder.Code)
	}
	if !HostedGatewayTrafficPath("/api/v1/gateway/mcp/x") || HostedGatewayTrafficPath("/api/v1/gateway/mcp/") || HostedGatewayTrafficPath("/api/v1/gateway/mcp-servers/x") || HostedGatewayTrafficPath("/api/v1/gateway/activity") {
		t.Fatal("the traffic paths are not exactly the gateway's two prefixes")
	}
}
