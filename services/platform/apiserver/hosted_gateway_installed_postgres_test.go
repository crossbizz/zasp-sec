package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/hostedgateway"
)

// TestHostedGatewayOnInstalledBaselinePostgres needs
// ZASP_BASELINE_RELEASE_TEST_DSN (see
// security_agent_remediation_installed_postgres_test.go). It proves the
// hosted gateway on an installed baseline, with nothing replaced but the
// decision of the authorization model and the two upstreams (an MCP server
// and a model provider, both local HTTPS servers):
//
//   - an administrator creates an API token with use_gateway through
//     zasp_authorization80_identity.create_pat, registers an MCP server and
//     saves the gateway policy, each in a checked request;
//   - an agent's requests arrive with that token, are authorized by
//     OpenFGAAuthorizer, and are served by the gateway's handler: each of its
//     two statements runs as the API login inside zasp_authorization80.fence;
//   - the decisions, the tools the server listed and the agent's activity
//     are read back from PostgreSQL, and through the activity route;
//   - a token without use_gateway is refused by the API server and by the
//     database's own fence, and the gateway's token reads nothing.
func TestHostedGatewayOnInstalledBaselinePostgres(t *testing.T) {
	baseline := startInstalledBaseline(t)
	ctx := baseline.ctx
	administrator := baseline.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := baseline.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(baseline.product)
	if err != nil {
		t.Fatalf("product repository on the installed baseline: %v", err)
	}
	// Token administration needs the deployment's two identity verifiers; a
	// bare installation gets a pair here, registered by the operator login.
	if registered := baseline.text(`SELECT count(*)::text FROM zasp_authorization80_identity.verifiers`); registered == "0" {
		seed := bytes.Repeat([]byte{0x63}, 32)
		session, sessionErr := authorization.NewIdentitySessionKey(seed)
		webhook, webhookErr := authorization.NewIdentityWebhookKey(seed)
		if sessionErr != nil || webhookErr != nil {
			t.Fatal(sessionErr, webhookErr)
		}
		operator := baseline.login("zasp_operator")
		audience := sha256.Sum256([]byte("https://zasp.test.invalid"))
		for statement, key := range map[string][2]any{
			`SELECT zasp_authorization80_identity.register_session($1,$2,$3,$4,$5,$6)`: {session.Version(), session.Verifier()},
			`SELECT zasp_authorization80_identity.register_webhook($1,$2,$3,$4,$5,$6)`: {webhook.Version(), webhook.Verifier()},
		} {
			if _, err := operator.Exec(ctx, statement, key[0], key[1], hex.EncodeToString(audience[:]), "project-test-installed", "zasp_svc_api", ""); err != nil {
				t.Fatalf("register identity verifier: %v", err)
			}
		}
	}
	token := func(name string, permissions string) installedPrincipal {
		t.Helper()
		raw := "zasp_pat_" + strings.ReplaceAll(baseline.id()[4:], "-", "") + strings.Repeat("A", 11)
		mutation := administrationMutation{Operation: "createAPIToken", ID: baseline.id(), Name: name, WorkspaceID: baseline.w, EnvironmentID: baseline.e, Permissions: json.RawMessage(permissions), ExpiresAt: time.Now().UTC().Add(time.Hour),
			IdempotencyKey: "create-token-" + strings.ReplaceAll(name, " ", "-") + "-" + baseline.e[4:12], GrantID: baseline.id(), AuditID: baseline.id(), revealKey: bytes.Repeat([]byte{0x52}, 32)}
		if err := prepareAPITokenReveal(administrator.identity, &mutation, mutation.Operation, raw, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		checked, err := baseline.checked(administrator, RoutedOperation{OperationID: "createAPIToken", PathParameters: map[string]string{"id": mutation.ID}})
		if err != nil {
			t.Fatalf("authorize createAPIToken: %v", err)
		}
		created, err := repository.MutateAdministration(checked, administrator.identity, mutation)
		if err != nil || !bytes.Contains(created, []byte(mutation.ID)) || bytes.Contains(created, []byte(raw)) {
			t.Fatalf("create token %s with %s: %s %v", name, permissions, created, err)
		}
		identity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: raw})
		if err != nil || identity.CredentialKind != CredentialBearerToken || identity.PrincipalID != administrator.identity.PrincipalID || identity.Scope != baseline.scope {
			t.Fatalf("authenticate token %s: %+v %v", name, identity, err)
		}
		return installedPrincipal{identity: identity, binding: identity.credentialBinding}
	}
	agentToken := token("Support agent gateway", `["use_gateway"]`)
	reader := token("Inventory reader", `["view"]`)
	decider := token("Decision gateway", `["decide_guardrails"]`)
	if strings.Join(agentToken.binding.PATCeiling, ",") != "use_gateway" {
		t.Fatalf("token permissions: %v", agentToken.binding.PATCeiling)
	}

	// The two upstreams. Their certificate is for example.com; the gateway's
	// client is the production one except that it connects to them whatever
	// the name resolves to.
	var mu sync.Mutex
	var upstreamCalls []map[string]any
	var upstreamAuthorization []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		var message map[string]any
		_ = json.Unmarshal(raw, &message)
		mu.Lock()
		upstreamCalls = append(upstreamCalls, message)
		upstreamAuthorization = append(upstreamAuthorization, request.Header.Get("Authorization")+"|"+request.Header.Get("x-api-key"))
		mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(request.URL.Path, "/chat/completions"):
			fmt.Fprint(writer, `{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"Write to owner@example.com."},"finish_reason":"stop"}]}`)
		case message["method"] == "tools/list":
			_ = json.NewEncoder(writer).Encode(map[string]any{"jsonrpc": "2.0", "id": message["id"], "result": map[string]any{"tools": []any{
				map[string]any{"name": "lookup_customer", "description": "Look a customer up.", "inputSchema": map[string]any{"type": "object"}},
				map[string]any{"name": "run_shell", "description": "Run a command.", "inputSchema": map[string]any{"type": "object"}}}}})
		default:
			_ = json.NewEncoder(writer).Encode(map[string]any{"jsonrpc": "2.0", "id": message["id"], "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "The customer is jane.customer@example.com."}}, "isError": false}})
		}
	}))
	defer upstream.Close()
	gateway, err := NewHostedGateway(HostedGatewayConfig{Timeout: 30 * time.Second, Providers: map[string]hostedgateway.Provider{
		"openai": {Name: "openai", BaseURL: "https://example.com/v1", KeyHeader: "Authorization", Paths: map[string]string{hostedgateway.APIChatCompletions: "/chat/completions"}}}})
	if err != nil {
		t.Fatal(err)
	}
	gateway.Client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	handler := &hostedGatewayHandler{database: baseline.product, newProductID: func() (string, error) { return baseline.id(), nil }, gateway: gateway}
	surface := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		routed, _ := RoutedOperationFromRequest(request)
		// Each request has its own correlation, as the middleware gives it.
		handler.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, baseline.id())), routed)
	})
	serverID := baseline.id()
	serverPath, trafficPath := "/api/v1/gateway/mcp-servers/"+serverID, "/api/v1/gateway/mcp/"+serverID
	mutation := func(version int64, key string) map[string]string {
		return map[string]string{"If-Match": installedVersion(version), "Idempotency-Key": key + "-" + baseline.e[4:12]}
	}

	// The administrator registers the server. The address is stored; no
	// credential of the upstream is.
	registered := baseline.serve(surface, administrator, "putMCPGatewayServer", http.MethodPut, serverPath, map[string]string{"id": serverID},
		`{"name":"Tickets","upstream_url":"https://example.com/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`, mutation(0, "gateway-server"))
	var server MCPGatewayServer
	if registered.Code != http.StatusCreated || json.Unmarshal(registered.Body.Bytes(), &server) != nil || server.ID != serverID || server.GatewayPath != trafficPath || server.Approval != "unapproved" || server.Version != 1 || registered.Header().Get("X-Audit-ID") == "" {
		t.Fatalf("register: %d %s", registered.Code, registered.Body.String())
	}
	if audit := baseline.text(`SELECT operation||' '||principal_id FROM zasp_workflow_audit WHERE audit_id=$1`, registered.Header().Get("X-Audit-ID")); audit != "putMCPGatewayServer "+administrator.identity.PrincipalID.String() {
		t.Fatalf("audit=%q", audit)
	}

	agentID := baseline.id()
	call := func(principal installedPrincipal, body string) (*httptest.ResponseRecorder, error) {
		t.Helper()
		checked, err := baseline.checked(principal, RoutedOperation{OperationID: "callMCPGateway", PathParameters: map[string]string{"id": serverID}})
		if err != nil {
			return nil, err
		}
		request := httptest.NewRequest(http.MethodPost, trafficPath, strings.NewReader(body)).WithContext(checked)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(hostedgateway.HeaderUpstreamAuthorization, "Bearer upstream-credential-of-the-test")
		request.Header.Set(hostedgateway.HeaderAgentID, agentID)
		recorder := httptest.NewRecorder()
		surface.ServeHTTP(recorder, request)
		return recorder, nil
	}
	const toolCall = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"lookup_customer","arguments":{"query":"the account of private.person@example.com, card 4111 1111 1111 1111"}}}`

	// The agent's tool call: the argument is redacted before the upstream
	// sees it, the result before the agent does, and both decisions are in
	// the database with a digest and no text.
	response, err := call(agentToken, toolCall)
	if err != nil || response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "The customer is [REDACTED:pii.email].") {
		t.Fatalf("tool call with the gateway token: %v %+v", err, response)
	}
	mu.Lock()
	sent, credential := upstreamCalls[len(upstreamCalls)-1], upstreamAuthorization[len(upstreamAuthorization)-1]
	mu.Unlock()
	if sent["params"].(map[string]any)["arguments"].(map[string]any)["query"] != "the account of [REDACTED:pii.email], card [REDACTED:pii.credit_card]" || credential != "Bearer upstream-credential-of-the-test|" {
		t.Fatalf("upstream saw %v with %q", sent, credential)
	}
	digest := sha256.Sum256([]byte(toolCall))
	if rows := baseline.text(`SELECT string_agg(direction||' '||decision||' '||reason||' '||tool_name||' '||agent_id||' '||principal_id||' '||(rules->0->>'id')||' '||CASE direction WHEN 'request' THEN bytes::text||' '||encode(content_digest,'hex') ELSE '' END,'; ' ORDER BY created_at)
FROM zasp_gateway_decisions WHERE(organization_id,workspace_id,environment_id,server_id)=($1,$2,$3,$4)`, baseline.o, baseline.w, baseline.e, serverID); rows != "request redact guardrail lookup_customer "+agentID+" "+administrator.identity.PrincipalID.String()+" pii.email "+strconv.Itoa(len(toolCall))+" "+hex.EncodeToString(digest[:])+
		"; response redact guardrail lookup_customer "+agentID+" "+administrator.identity.PrincipalID.String()+" pii.email " {
		t.Fatalf("decision records=%q", rows)
	}
	if leaked := baseline.text(`SELECT count(*)::text FROM zasp_gateway_decisions d WHERE d.server_id=$1 AND(to_jsonb(d)::text LIKE '%4111%' OR to_jsonb(d)::text ILIKE '%private.person%' OR to_jsonb(d)::text ILIKE '%jane.customer%' OR to_jsonb(d)::text ILIKE '%upstream-credential%')`, serverID); leaked != "0" {
		t.Fatal("a decision record holds text of the call or the upstream's credential")
	}
	if stored := baseline.text(`SELECT count(*)::text FROM zasp_mcp_gateway_servers s WHERE s.id=$1 AND to_jsonb(s)::text ILIKE '%upstream-credential%'`, serverID); stored != "0" {
		t.Fatal("the upstream's credential was stored")
	}
	// The agent's traffic is its activity.
	if activity := baseline.text(`SELECT zasp_inventory_agent_activity($1,$2,$3,$4,'agent','{}'::jsonb,NULL)->>'activity_state'`, baseline.o, baseline.w, baseline.e, agentID); activity != "active" {
		t.Fatalf("agent activity=%s", activity)
	}

	// The tool list: the tools are noted for the inventory.
	if response, err = call(agentToken, `{"jsonrpc":"2.0","id":8,"method":"tools/list"}`); err != nil || response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "run_shell") {
		t.Fatalf("tools/list: %v %+v", err, response)
	}
	if tools := baseline.text(`SELECT string_agg(name||':'||risk,',' ORDER BY name) FROM zasp_mcp_gateway_tools WHERE(organization_id,workspace_id,environment_id,server_id)=($1,$2,$3,$4)`, baseline.o, baseline.w, baseline.e, serverID); tools != "lookup_customer:read,run_shell:execute" {
		t.Fatalf("tools=%s", tools)
	}

	// The administrator's policy: tools that run commands are denied and an
	// unapproved server is refused. It applies to the next request.
	saved := baseline.serve(surface, administrator, "putGatewayPolicy", http.MethodPut, "/api/v1/gateway/policy", nil, `{"unapproved_servers":"refuse","denied_tool_risks":["execute"],"requests_per_minute":600}`, mutation(0, "gateway-policy"))
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), `"version":1`) || !strings.Contains(saved.Body.String(), `"gateway_enabled":true`) {
		t.Fatalf("policy: %d %s", saved.Code, saved.Body.String())
	}
	mu.Lock()
	before := len(upstreamCalls)
	mu.Unlock()
	if response, err = call(agentToken, toolCall); err != nil || response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "not approved") {
		t.Fatalf("an unapproved server under a refusing policy: %v %+v", err, response)
	}
	mu.Lock()
	after := len(upstreamCalls)
	mu.Unlock()
	if after != before {
		t.Fatal("a refused request was forwarded")
	}
	if refusal := baseline.text(`SELECT decision||' '||reason||' '||policy_version::text FROM zasp_gateway_decisions WHERE server_id=$1 ORDER BY created_at DESC LIMIT 1`, serverID); refusal != "block server_unapproved 1" {
		t.Fatalf("refusal record=%q", refusal)
	}
	// Approved in the MCP registry, the server is served again, without the
	// tool the policy denies.
	baseline.exec(`INSERT INTO zasp_mcp_registry(organization_id,workspace_id,environment_id,identity,status,updated_by) VALUES($1,$2,$3,'host:example.com','approved',$4)`, baseline.o, baseline.w, baseline.e, administrator.identity.PrincipalID.String())
	if response, err = call(agentToken, `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`); err != nil || response.Code != http.StatusOK || strings.Contains(response.Body.String(), "run_shell") || !strings.Contains(response.Body.String(), "lookup_customer") {
		t.Fatalf("tools/list under the policy: %v %+v", err, response)
	}
	if response, err = call(agentToken, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"id"}}}`); err != nil || response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"isError":true`) {
		t.Fatalf("a denied tool: %v %+v", err, response)
	}
	baseline.exec(`UPDATE zasp_mcp_registry SET status='blocked' WHERE(organization_id,workspace_id,environment_id,identity)=($1,$2,$3,'host:example.com')`, baseline.o, baseline.w, baseline.e)
	if response, err = call(agentToken, toolCall); err != nil || response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "blocked in the MCP registry") {
		t.Fatalf("a blocked server: %v %+v", err, response)
	}

	// A model request through the proxy, with the provider's key in its
	// header.
	chatRoute := RoutedOperation{OperationID: "createGatewayChatCompletion", PathParameters: map[string]string{}}
	checked, err := baseline.checked(agentToken, chatRoute)
	if err != nil {
		t.Fatal(err)
	}
	const prompt = `{"model":"gpt-test","messages":[{"role":"user","content":"Who owns the account? My SSN is 078-05-1120."}]}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/llm/v1/chat/completions", strings.NewReader(prompt)).WithContext(checked)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(hostedgateway.HeaderUpstreamAuthorization, "Bearer provider-key-of-the-test")
	request.Header.Set(hostedgateway.HeaderAgentID, agentID)
	recorder := httptest.NewRecorder()
	surface.ServeHTTP(recorder, request)
	mu.Lock()
	sent, credential = upstreamCalls[len(upstreamCalls)-1], upstreamAuthorization[len(upstreamAuthorization)-1]
	mu.Unlock()
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Write to [REDACTED:pii.email].") || credential != "Bearer provider-key-of-the-test|" ||
		sent["messages"].([]any)[0].(map[string]any)["content"] != "Who owns the account? My SSN is [REDACTED:pii.us_ssn]." {
		t.Fatalf("chat completion: %d %s; provider saw %v with %q", recorder.Code, recorder.Body.String(), sent, credential)
	}
	if rows := baseline.text(`SELECT string_agg(direction||' '||decision||' '||operation||' '||provider||' '||model||' '||(rules->0->>'id'),'; ' ORDER BY created_at) FROM zasp_gateway_decisions WHERE(organization_id,workspace_id,environment_id,surface)=($1,$2,$3,'llm')`, baseline.o, baseline.w, baseline.e); rows != "request redact chat.completions openai gpt-test pii.us_ssn; response redact chat.completions openai gpt-test pii.email" {
		t.Fatalf("model records=%q", rows)
	}
	if leaked := baseline.text(`SELECT count(*)::text FROM zasp_gateway_decisions d WHERE(d.organization_id,d.workspace_id,d.environment_id)=($1,$2,$3) AND(to_jsonb(d)::text LIKE '%078-05%' OR to_jsonb(d)::text ILIKE '%owns the account%' OR to_jsonb(d)::text ILIKE '%provider-key%')`, baseline.o, baseline.w, baseline.e); leaked != "0" {
		t.Fatal("a decision record holds text of the prompt or the provider's key")
	}

	// The activity route, read by the administrator.
	activity := baseline.serve(surface, administrator, "listGatewayActivity", http.MethodGet, "/api/v1/gateway/activity?surface=mcp&decision=block&limit=2", nil, "", nil)
	var page struct {
		Items      []GatewayDecision `json:"items"`
		NextCursor *string           `json:"next_cursor"`
	}
	if activity.Code != http.StatusOK || json.Unmarshal(activity.Body.Bytes(), &page) != nil || len(page.Items) != 2 || page.NextCursor == nil || page.Items[0].Reason != "server_blocked" || page.Items[1].Reason != "tool_risk_denied" || *page.Items[0].ServerName != "Tickets" || *page.Items[0].AgentID != agentID {
		t.Fatalf("activity: %d %s", activity.Code, activity.Body.String())
	}
	listed := baseline.serve(surface, administrator, "listMCPGatewayServers", http.MethodGet, "/api/v1/gateway/mcp-servers", nil, "", nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"approval":"blocked"`) || !strings.Contains(listed.Body.String(), `"tool_count":2`) || !strings.Contains(listed.Body.String(), `"gateway_enabled":true`) || strings.Contains(listed.Body.String(), `"last_activity_at":null`) {
		t.Fatalf("servers: %d %s", listed.Code, listed.Body.String())
	}

	// A token without use_gateway is refused by the API server, and a proof
	// for it does not pass the database's own fence.
	for name, principal := range map[string]installedPrincipal{"a reading token": reader, "a decision token": decider, "the administrator's session": administrator} {
		if _, err := call(principal, toolCall); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("%s was authorized for the gateway: %v", name, err)
		}
	}
	forged := func(principal installedPrincipal, operation string, parameters map[string]string) error {
		t.Helper()
		granted, err := baseline.checked(agentToken, RoutedOperation{OperationID: "callMCPGateway", PathParameters: map[string]string{"id": serverID}})
		if err != nil {
			t.Fatal(err)
		}
		grant, _ := requestAuthorizationFromContext(granted)
		grant.OperationID, grant.Credential, grant.Identity, grant.PathParameters = operation, principal.binding, principal.identity, parameters
		if grant, err = attestAuthorization(grant, baseline.authorizer.AttestationKey, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		proof, err := authorizationProofJSON(grant)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := baseline.login("zasp_svc_api").Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		_, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof))
		return err
	}
	if err := forged(agentToken, "callMCPGateway", map[string]string{"id": serverID}); err != nil {
		t.Fatalf("the gateway token's own proof was refused: %v", err)
	}
	if err := forged(reader, "callMCPGateway", map[string]string{"id": serverID}); err == nil {
		t.Fatal("the database accepted a gateway proof for a token with view alone")
	}
	// The gateway's token reads nothing and changes nothing.
	for _, route := range []RoutedOperation{
		{OperationID: "getGatewayPolicy", PathParameters: map[string]string{}}, {OperationID: "putGatewayPolicy", PathParameters: map[string]string{}}, {OperationID: "listGatewayActivity", PathParameters: map[string]string{}},
		{OperationID: "listMCPGatewayServers", PathParameters: map[string]string{}}, {OperationID: "putMCPGatewayServer", PathParameters: map[string]string{"id": serverID}}, {OperationID: "listAgents", PathParameters: map[string]string{}},
		{OperationID: "createGuardrailDecision", PathParameters: map[string]string{}},
	} {
		if _, err := baseline.checked(agentToken, route); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("the gateway token was authorized for %s: %v", route.OperationID, err)
		}
		if err := forged(agentToken, route.OperationID, route.PathParameters); err == nil {
			t.Fatalf("the database accepted a %s proof for the gateway token", route.OperationID)
		}
	}
	// With the gateway token's proof for one server, the database serves the
	// session of that server and nothing else of the gateway.
	trafficRoute := RoutedOperation{OperationID: "callMCPGateway", PathParameters: map[string]string{"id": serverID}}
	principalID := agentToken.identity.PrincipalID.String()
	if raw, err := baseline.fenced("zasp_svc_api", agentToken, trafficRoute, currentGatewayOpenSQL, baseline.o, baseline.w, baseline.e, principalID, "callMCPGateway", serverID); err != nil || !strings.Contains(string(raw), `"approval": "blocked"`) {
		t.Fatalf("the gateway token's session: %s %v", raw, err)
	}
	otherServer := baseline.id()
	for name, statement := range map[string]struct {
		sql       string
		arguments []any
	}{
		"another server":        {currentGatewayOpenSQL, []any{baseline.o, baseline.w, baseline.e, principalID, "callMCPGateway", otherServer}},
		"another operation":     {currentGatewayOpenSQL, []any{baseline.o, baseline.w, baseline.e, principalID, "createGatewayMessage", ""}},
		"the policy":            {currentGatewayPolicySQL, []any{baseline.o, baseline.w, baseline.e}},
		"the activity":          {currentGatewayActivitySQL, []any{baseline.o, baseline.w, baseline.e, "", "", "", "", "", 10}},
		"the server list":       {currentGatewayServerPageSQL, []any{baseline.o, baseline.w, baseline.e}},
		"the guardrail policy":  {currentGuardrailPolicySQL, []any{baseline.o, baseline.w, baseline.e}},
		"a guardrail decision":  {currentGuardrailDecideSQL, []any{baseline.o, baseline.w, baseline.e, principalID, `{"id":"` + baseline.id() + `","direction":"input","input_bytes":1,"content_digest":"sha256:` + strings.Repeat("ab", 32) + `","agent_id":null,"tool_name":null,"matched":[]}`}},
		"a record as another":   {currentGatewayRecordSQL, []any{baseline.o, baseline.w, baseline.e, reader.identity.PrincipalID.String() + "x", "callMCPGateway", serverID, `{"records":[],"tools":[]}`}},
		"a record of a removed": {currentGatewayRecordSQL, []any{baseline.o, baseline.w, baseline.e, principalID, "callMCPGateway", otherServer, `{"records":[],"tools":[]}`}},
	} {
		if raw, err := baseline.fenced("zasp_svc_api", agentToken, trafficRoute, statement.sql, statement.arguments...); err == nil {
			t.Fatalf("with the gateway token's proof the database served %s: %s", name, raw)
		}
	}
	// A reading token's proof opens no gateway session either.
	if raw, err := baseline.fenced("zasp_svc_api", reader, RoutedOperation{OperationID: "getGatewayPolicy", PathParameters: map[string]string{}}, currentGatewayOpenSQL, baseline.o, baseline.w, baseline.e, reader.identity.PrincipalID.String(), "callMCPGateway", serverID); err == nil {
		t.Fatalf("a reading token opened a gateway session: %s", raw)
	}
	// A member whose view of the Environment is taken away sends nothing
	// through the gateway with a token they created.
	baseline.refused[administrator.identity.PrincipalID.String()+" view"] = true
	if _, err := call(agentToken, toolCall); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("a token whose owner cannot view the Environment was authorized: %v", err)
	}
	delete(baseline.refused, administrator.identity.PrincipalID.String()+" view")

	// A record written after the request's proof has aged (the end of a
	// long stream) is written under a fresh decision of the authorizer, and
	// the database takes it.
	late, err := baseline.checked(agentToken, chatRoute)
	if err != nil {
		t.Fatal(err)
	}
	store := &gatewayRequestStore{handler: handler, identity: agentToken.identity, route: chatRoute, issued: time.Now().Add(-gatewayProofAge - time.Second)}
	records := []hostedgateway.Record{{Surface: "llm", Operation: "messages", Direction: "response", Decision: "allow", Reason: "none", Bytes: 9, Digest: "sha256:" + strings.Repeat("cd", 32), Provider: "anthropic", Model: "claude-test"}}
	if err := store.Record(context.WithoutCancel(late), "", records, nil); err != nil {
		t.Fatalf("a late record under a fresh decision: %v", err)
	}
	if written := baseline.text(`SELECT count(*)::text FROM zasp_gateway_decisions WHERE(organization_id,workspace_id,environment_id,provider)=($1,$2,$3,'anthropic')`, baseline.o, baseline.w, baseline.e); written != "1" {
		t.Fatalf("late records=%s", written)
	}

	// The administrator removes the server; its records stay.
	removed := baseline.serve(surface, administrator, "deleteMCPGatewayServer", http.MethodDelete, serverPath, map[string]string{"id": serverID}, "", mutation(1, "gateway-server-remove"))
	if removed.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", removed.Code, removed.Body.String())
	}
	if response, err = call(agentToken, toolCall); err != nil || response.Code != http.StatusNotFound {
		t.Fatalf("a removed server: %v %+v", err, response)
	}
	if kept := baseline.text(`SELECT (count(*)>=6)::text FROM zasp_gateway_decisions WHERE server_id=$1`, serverID); kept != "true" {
		t.Fatal("the records of a removed server were removed")
	}
}
