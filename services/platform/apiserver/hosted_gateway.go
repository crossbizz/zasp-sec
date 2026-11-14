package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/guardrail"
	"github.com/zasp-ai/zasp-sec/services/platform/hostedgateway"
)

// The hosted gateway (completion.sql, section WS9). The platform hosts an MCP
// gateway and a model proxy; an agent's configuration names these addresses
// instead of the MCP server's or the provider's, with an API token that holds
// use_gateway:
//
//	POST   /api/v1/gateway/mcp/{id}                  callMCPGateway
//	DELETE /api/v1/gateway/mcp/{id}                  closeMCPGatewaySession
//	POST   /api/v1/gateway/llm/v1/chat/completions   createGatewayChatCompletion
//	POST   /api/v1/gateway/llm/v1/responses          createGatewayResponse
//	POST   /api/v1/gateway/llm/v1/messages           createGatewayMessage
//
// and the people who run the Environment manage it:
//
//	GET    /api/v1/gateway/policy             getGatewayPolicy
//	PUT    /api/v1/gateway/policy             putGatewayPolicy
//	GET    /api/v1/gateway/mcp-servers        listMCPGatewayServers
//	PUT    /api/v1/gateway/mcp-servers/{id}   putMCPGatewayServer
//	DELETE /api/v1/gateway/mcp-servers/{id}   deleteMCPGatewayServer
//	GET    /api/v1/gateway/activity           listGatewayActivity
//
// A prompt, an argument, a tool result or an answer exists only in this
// process for the duration of its request. The two statements of a traffic
// request carry the policy out and the decision records in; a record has no
// member that could hold text.

const (
	currentGatewayOpenSQL         = `SELECT zasp_authorization80.gateway_open($1,$2,$3,$4,$5,NULLIF($6,''))`
	currentGatewayRecordSQL       = `SELECT zasp_authorization80.gateway_record($1,$2,$3,$4,$5,NULLIF($6,''),$7::jsonb)`
	currentGatewayPolicySQL       = `SELECT zasp_authorization80.gateway_policy($1,$2,$3)`
	currentGatewaySetPolicySQL    = `SELECT zasp_authorization80.gateway_set_policy($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`
	currentGatewayServerPageSQL   = `SELECT zasp_authorization80.mcp_gateway_server_page($1,$2,$3)`
	currentGatewayServerPutSQL    = `SELECT zasp_authorization80.mcp_gateway_server_put($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)`
	currentGatewayServerDeleteSQL = `SELECT zasp_authorization80.mcp_gateway_server_delete($1,$2,$3,$4,$5,$6,$7,$8)`
	currentGatewayActivitySQL     = `SELECT zasp_authorization80.gateway_activity_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),$9)`

	// The path prefixes of the gateway's traffic. Requests under them may be
	// larger and may last longer than the product API's (see
	// HostedGatewayTrafficPath).
	hostedGatewayMCPPrefix = "/api/v1/gateway/mcp/"
	hostedGatewayLLMPrefix = "/api/v1/gateway/llm/"

	// A proof is attested for one minute. A record written later than this
	// after its request was authorized is written under a fresh decision.
	gatewayProofAge = 40 * time.Second
)

// PermissionUseGateway is the permission of the hosted gateway's traffic and
// of nothing else. Like decide_guardrails it is a permission of an API token
// only: no role holds it and no browser session carries it. A token that
// holds it alone can send requests through the gateway and cannot read the
// Environment's inventory, findings, policy or activity.
const PermissionUseGateway = "use_gateway"

// HostedGatewayTrafficPath reports whether a request path is one of the
// gateway's traffic routes: the routes whose bodies are prompts and tool
// calls, and whose answers may be streams.
func HostedGatewayTrafficPath(path string) bool {
	for _, prefix := range []string{hostedGatewayMCPPrefix, hostedGatewayLLMPrefix} {
		if len(path) > len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func hostedGatewayTrafficOperation(operation string) bool {
	return stringIn(operation, "callMCPGateway", "closeMCPGatewaySession", "createGatewayChatCompletion", "createGatewayResponse", "createGatewayMessage")
}

// HostedGatewayConfig is the deployment's setting of the gateway's traffic.
type HostedGatewayConfig struct {
	// Timeout bounds one exchange, a stream included.
	Timeout time.Duration
	// Upstream bounds the outbound connections. Its zero value connects to
	// public addresses only.
	Upstream hostedgateway.UpstreamConfig
	// Providers are the model providers the proxy forwards to. Nil means
	// the catalog the platform ships.
	Providers map[string]hostedgateway.Provider
	// AllowUpstreamURL decides whether a registered MCP address is
	// forwarded to. Nil means hostedgateway.ValidUpstreamURL.
	AllowUpstreamURL func(string) bool
}

// NewHostedGateway builds the engine of the gateway's traffic.
func NewHostedGateway(config HostedGatewayConfig) (*hostedgateway.Gateway, error) {
	if config.Timeout < time.Second || config.Timeout > 30*time.Minute {
		return nil, ErrRepositoryConfiguration
	}
	providers := config.Providers
	if providers == nil {
		providers = hostedgateway.DefaultProviders()
	}
	upstream := config.Upstream
	if upstream.ResponseHeaderTimeout <= 0 {
		upstream.ResponseHeaderTimeout = config.Timeout
	}
	return &hostedgateway.Gateway{Client: hostedgateway.NewUpstreamClient(upstream), Limiter: hostedgateway.NewRateLimiter(nil), Timeout: config.Timeout, Providers: providers, AllowUpstreamURL: config.AllowUpstreamURL}, nil
}

type hostedGatewayHandler struct {
	database     JSONDatabase
	newProductID func() (string, error)
	// gateway is the engine of the traffic routes. It is nil where the
	// deployment does not host the gateway: the traffic routes then answer
	// 404, and the management routes say the gateway is not enabled.
	gateway *hostedgateway.Gateway
}

func (handler *hostedGatewayHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch routed.OperationID {
	case "callMCPGateway", "closeMCPGatewaySession", "createGatewayChatCompletion", "createGatewayResponse", "createGatewayMessage":
		handler.traffic(writer, request, identity, routed)
	case "getGatewayPolicy":
		handler.getPolicy(writer, request, identity)
	case "putGatewayPolicy":
		handler.putPolicy(writer, request, identity)
	case "listMCPGatewayServers":
		handler.listServers(writer, request, identity)
	case "putMCPGatewayServer":
		handler.putServer(writer, request, identity, routed.PathParameters["id"])
	case "deleteMCPGatewayServer":
		handler.deleteServer(writer, request, identity, routed.PathParameters["id"])
	case "listGatewayActivity":
		handler.listActivity(writer, request, identity)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

// traffic hands one request of an agent to the engine.
func (handler *hostedGatewayHandler) traffic(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	if handler.gateway == nil {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	// An agent authenticates with an API token.
	if identity.CredentialKind != CredentialBearerToken || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	// A stream outlives the server's write deadline, which is sized for the
	// product API's short answers and would cut it. The body was read
	// before the handler ran, so the read deadline needs no change.
	_ = http.NewResponseController(writer).SetWriteDeadline(time.Now().Add(handler.gateway.Timeout + 15*time.Second))
	store := &gatewayRequestStore{handler: handler, identity: identity, route: routed, issued: time.Now()}
	caller := hostedgateway.Caller{Store: store, TokenKey: identity.credentialBinding.ID}
	if caller.TokenKey == "" {
		caller.TokenKey = identity.PrincipalID.String()
	}
	if routed.OperationID == "closeMCPGatewaySession" {
		if request.Method != http.MethodDelete {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		handler.gateway.CloseMCP(writer, request, caller, routed.PathParameters["id"])
		return
	}
	if request.Method != http.MethodPost || request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) == 0 {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	switch routed.OperationID {
	case "callMCPGateway":
		handler.gateway.ServeMCP(writer, request, caller, routed.PathParameters["id"], body)
	case "createGatewayChatCompletion":
		handler.gateway.ServeLLM(writer, request, caller, hostedgateway.APIChatCompletions, body)
	case "createGatewayResponse":
		handler.gateway.ServeLLM(writer, request, caller, hostedgateway.APIResponses, body)
	case "createGatewayMessage":
		handler.gateway.ServeLLM(writer, request, caller, hostedgateway.APIMessages, body)
	}
}

// gatewayRequestStore is the engine's Store for one request of one token:
// two statements, each inside the request's checked authorization.
type gatewayRequestStore struct {
	handler  *hostedGatewayHandler
	identity RequestIdentity
	route    RoutedOperation
	mu       sync.Mutex
	issued   time.Time
	grant    *RequestAuthorization
}

func (store *gatewayRequestStore) scope() []any {
	scope := store.identity.Scope
	return []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), store.identity.PrincipalID.String(), store.route.OperationID}
}

// current returns the context of a statement: the request's own proof while
// it is fresh, and a new decision of the same authorizer for the same token
// once it is not (the end of a long stream).
func (store *gatewayRequestStore) current(ctx context.Context) context.Context {
	store.mu.Lock()
	defer store.mu.Unlock()
	if time.Since(store.issued) < gatewayProofAge {
		if store.grant != nil {
			return context.WithValue(ctx, requestAuthorizationContextKey{}, *store.grant)
		}
		return ctx
	}
	authorizer, available := ctx.Value(requestAuthorizerContextKey{}).(RequestAuthorizer)
	if !available || nilInterface(authorizer) {
		return ctx
	}
	grant, err := authorizer.Authorize(context.WithValue(ctx, authorizationQueryContextKey{}, url.Values{}), store.identity, store.identity.credentialBinding, store.route)
	if err != nil || grant.OperationID != store.route.OperationID || grant.Identity.PrincipalID != store.identity.PrincipalID || grant.Identity.Scope != store.identity.Scope {
		// The statement is then refused under the stale proof.
		return ctx
	}
	store.grant, store.issued = &grant, time.Now()
	return context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
}

func gatewayStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrRepositoryNotFound):
		return hostedgateway.ErrNotFound
	case errors.Is(err, ErrAuthorizationDenied), errors.Is(err, ErrRepositoryAuthorization):
		return hostedgateway.ErrForbidden
	}
	return errors.Join(hostedgateway.ErrUnavailable, err)
}

type gatewayPolicyWire struct {
	Version           int64    `json:"version"`
	UnapprovedServers string   `json:"unapproved_servers"`
	DeniedToolRisks   []string `json:"denied_tool_risks"`
	RequestsPerMinute int      `json:"requests_per_minute"`
}

func (policy gatewayPolicyWire) valid() bool {
	if policy.Version < 0 || policy.Version > 1000000 || !stringIn(policy.UnapprovedServers, "allow", "refuse") || policy.DeniedToolRisks == nil || len(policy.DeniedToolRisks) > 5 || policy.RequestsPerMinute < 0 || policy.RequestsPerMinute > 100000 {
		return false
	}
	seen := map[string]bool{}
	for _, risk := range policy.DeniedToolRisks {
		if !stringIn(risk, "execute", "write", "network", "read", "unclassified") || seen[risk] {
			return false
		}
		seen[risk] = true
	}
	return true
}

func (store *gatewayRequestStore) Open(ctx context.Context, serverID string) (hostedgateway.Session, error) {
	raw, err := store.handler.database.QueryJSON(store.current(ctx), currentGatewayOpenSQL, append(store.scope(), serverID)...)
	if err != nil {
		return hostedgateway.Session{}, gatewayStoreError(err)
	}
	var wire struct {
		Policy    gatewayPolicyWire `json:"policy"`
		Guardrail struct {
			Version int64             `json:"version"`
			Rules   map[string]string `json:"rules"`
		} `json:"guardrail"`
		Server *struct {
			ID           string   `json:"id"`
			Name         string   `json:"name"`
			UpstreamURL  string   `json:"upstream_url"`
			Enabled      bool     `json:"enabled"`
			AllowedTools []string `json:"allowed_tools"`
			DeniedTools  []string `json:"denied_tools"`
			Approval     string   `json:"approval"`
		} `json:"server"`
		RateAllowed *bool `json:"rate_allowed"`
	}
	if !exactJSONFields(raw, "guardrail", "policy", "rate_allowed", "server") || decodeStrictDiscovery(raw, &wire) != nil || wire.RateAllowed == nil || !wire.Policy.valid() || wire.Guardrail.Rules == nil || wire.Guardrail.Version < 0 || (wire.Server == nil) != (serverID == "") {
		return hostedgateway.Session{}, hostedgateway.ErrUnavailable
	}
	session := hostedgateway.Session{Policy: hostedgateway.Policy{Version: wire.Policy.Version, UnapprovedServers: wire.Policy.UnapprovedServers, DeniedToolRisks: wire.Policy.DeniedToolRisks, RequestsPerMinute: wire.Policy.RequestsPerMinute},
		Guardrail: hostedgateway.Modes{}, GuardrailVersion: wire.Guardrail.Version, RateDecided: true, RateAllowed: *wire.RateAllowed}
	for id, mode := range wire.Guardrail.Rules {
		rule, known := guardrail.RuleByID(id)
		if !known || !guardrail.ValidMode(rule, guardrail.Mode(mode)) {
			// A stored rule the catalog does not have is not applied.
			return hostedgateway.Session{}, hostedgateway.ErrUnavailable
		}
		session.Guardrail[id] = guardrail.Mode(mode)
	}
	if wire.Server != nil {
		server := wire.Server
		if server.ID != serverID || server.Name == "" || server.AllowedTools == nil || server.DeniedTools == nil || !stringIn(server.Approval, "approved", "unapproved", "blocked") {
			return hostedgateway.Session{}, hostedgateway.ErrUnavailable
		}
		session.Server = &hostedgateway.Server{ID: server.ID, Name: server.Name, UpstreamURL: server.UpstreamURL, Enabled: server.Enabled, AllowedTools: server.AllowedTools, DeniedTools: server.DeniedTools, Approval: server.Approval}
	}
	return session, nil
}

// gatewayRecordWire is everything of a request that reaches the database. It
// has no member that could hold a prompt, an argument, a result or an answer.
type gatewayRecordWire struct {
	ID            string                      `json:"id"`
	Surface       string                      `json:"surface"`
	Operation     string                      `json:"operation"`
	Direction     string                      `json:"direction"`
	Decision      string                      `json:"decision"`
	Reason        string                      `json:"reason"`
	Rules         []hostedgateway.MatchedRule `json:"rules"`
	Bytes         int64                       `json:"bytes"`
	ContentDigest string                      `json:"content_digest"`
	ToolName      *string                     `json:"tool_name"`
	Provider      *string                     `json:"provider"`
	Model         *string                     `json:"model"`
	AgentID       *string                     `json:"agent_id"`
}

type gatewayToolWire struct {
	Name string `json:"name"`
	Risk string `json:"risk"`
}

type gatewayRecordBatch struct {
	Records []gatewayRecordWire `json:"records"`
	Tools   []gatewayToolWire   `json:"tools"`
}

func (store *gatewayRequestStore) Record(ctx context.Context, serverID string, records []hostedgateway.Record, tools []hostedgateway.ToolSeen) error {
	optional := func(value string) *string {
		if value == "" {
			return nil
		}
		return &value
	}
	batch := gatewayRecordBatch{Records: []gatewayRecordWire{}, Tools: []gatewayToolWire{}}
	for _, record := range records {
		id, err := store.handler.newProductID()
		if err != nil || !validProductID(id) {
			return hostedgateway.ErrUnavailable
		}
		rules := record.Rules
		if rules == nil {
			rules = []hostedgateway.MatchedRule{}
		}
		batch.Records = append(batch.Records, gatewayRecordWire{ID: id, Surface: record.Surface, Operation: record.Operation, Direction: record.Direction, Decision: record.Decision, Reason: record.Reason, Rules: rules,
			Bytes: record.Bytes, ContentDigest: record.Digest, ToolName: optional(record.ToolName), Provider: optional(record.Provider), Model: optional(record.Model), AgentID: optional(record.AgentID)})
	}
	for _, tool := range tools {
		batch.Tools = append(batch.Tools, gatewayToolWire{Name: tool.Name, Risk: tool.Risk})
	}
	// One statement takes eight records; a request makes at most a few.
	for len(batch.Records) > 0 || len(batch.Tools) > 0 {
		part := gatewayRecordBatch{Records: batch.Records, Tools: batch.Tools}
		if len(part.Records) > 8 {
			part.Records = part.Records[:8]
		}
		batch.Records, batch.Tools = batch.Records[len(part.Records):], []gatewayToolWire{}
		payload, err := json.Marshal(part)
		if err != nil {
			return hostedgateway.ErrUnavailable
		}
		raw, err := store.handler.database.QueryJSON(store.current(ctx), currentGatewayRecordSQL, append(store.scope(), serverID, json.RawMessage(payload))...)
		if err != nil {
			return gatewayStoreError(err)
		}
		var result struct {
			Recorded int `json:"recorded"`
		}
		if !exactJSONFields(raw, "recorded") || decodeStrictDiscovery(raw, &result) != nil || result.Recorded != len(part.Records) {
			return hostedgateway.ErrUnavailable
		}
	}
	return nil
}

// GatewayPolicy is the gateway policy of an Environment. Version is 0 while
// the defaults apply. GatewayEnabled says whether this deployment hosts the
// gateway's traffic routes.
type GatewayPolicy struct {
	EnvironmentID     string     `json:"environment_id"`
	UnapprovedServers string     `json:"unapproved_servers"`
	DeniedToolRisks   []string   `json:"denied_tool_risks"`
	RequestsPerMinute int        `json:"requests_per_minute"`
	Version           int64      `json:"version"`
	UpdatedAt         *time.Time `json:"updated_at"`
	GatewayEnabled    bool       `json:"gateway_enabled"`
}

func (handler *hostedGatewayHandler) decodePolicy(raw json.RawMessage, environmentID string, extra ...string) (GatewayPolicy, error) {
	var wire struct {
		gatewayPolicyWire
		EnvironmentID string     `json:"environment_id"`
		UpdatedAt     *time.Time `json:"updated_at"`
		AuditID       string     `json:"audit_id"`
		CorrelationID string     `json:"correlation_id"`
	}
	fields := append([]string{"denied_tool_risks", "environment_id", "requests_per_minute", "unapproved_servers", "updated_at", "version"}, extra...)
	if !exactJSONFields(raw, fields...) || decodeStrictDiscovery(raw, &wire) != nil || wire.EnvironmentID != environmentID || !wire.valid() || (wire.Version == 0) != (wire.UpdatedAt == nil) {
		return GatewayPolicy{}, ErrRepositoryUnavailable
	}
	return GatewayPolicy{EnvironmentID: wire.EnvironmentID, UnapprovedServers: wire.UnapprovedServers, DeniedToolRisks: wire.DeniedToolRisks, RequestsPerMinute: wire.RequestsPerMinute, Version: wire.Version, UpdatedAt: wire.UpdatedAt, GatewayEnabled: handler.gateway != nil}, nil
}

func gatewayScope(identity RequestIdentity) (string, string, string) {
	return identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
}

func gatewayManagementCredential(identity RequestIdentity) bool {
	return stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken))
}

func (handler *hostedGatewayHandler) getPolicy(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !gatewayManagementCredential(identity) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	o, w, e := gatewayScope(identity)
	raw, err := handler.database.QueryJSON(request.Context(), currentGatewayPolicySQL, o, w, e)
	if err != nil {
		writeProductionError(writer, request, discoveryProviderError(err))
		return
	}
	policy, err := handler.decodePolicy(raw, e)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(policy.Version))
	writeJSONValue(writer, request, http.StatusOK, policy, nil)
}

func (handler *hostedGatewayHandler) mutationIDs(request *http.Request) (string, string, bool) {
	auditID, err := handler.newProductID()
	correlationID := correlationIDFromContext(request.Context())
	return auditID, correlationID, err == nil && validProductID(auditID) && validProductID(correlationID) && auditID != correlationID
}

func (handler *hostedGatewayHandler) putPolicy(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	// The optimistic version makes a repeated request safe: the second one
	// names a version that is no longer current and is refused.
	_, expectedVersion, valid := discoveryMutationHeaders(request, true)
	var input struct {
		UnapprovedServers *string   `json:"unapproved_servers"`
		DeniedToolRisks   *[]string `json:"denied_tool_risks"`
		RequestsPerMinute *int      `json:"requests_per_minute"`
	}
	if request.Method != http.MethodPut || request.URL.RawQuery != "" || !valid || !gatewayManagementCredential(identity) || decodeProductionJSON(request, &input) != nil ||
		input.UnapprovedServers == nil || input.DeniedToolRisks == nil || input.RequestsPerMinute == nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	policy := gatewayPolicyWire{UnapprovedServers: *input.UnapprovedServers, DeniedToolRisks: *input.DeniedToolRisks, RequestsPerMinute: *input.RequestsPerMinute}
	if !policy.valid() {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	payload, err := json.Marshal(map[string]any{"unapproved_servers": policy.UnapprovedServers, "denied_tool_risks": policy.DeniedToolRisks, "requests_per_minute": policy.RequestsPerMinute})
	auditID, correlationID, ids := handler.mutationIDs(request)
	if err != nil || !ids {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	o, w, e := gatewayScope(identity)
	raw, err := handler.database.QueryJSON(request.Context(), currentGatewaySetPolicySQL, o, w, e, identity.PrincipalID.String(), json.RawMessage(payload), expectedVersion, auditID, correlationID)
	if err != nil {
		writeProductionError(writer, request, discoveryProviderError(err))
		return
	}
	saved, err := handler.decodePolicy(raw, e, "audit_id", "correlation_id")
	if err != nil || saved.Version != expectedVersion+1 {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeDiscoveryMutationHeaders(writer, saved.Version, auditID, "")
	writeJSONValue(writer, request, http.StatusOK, saved, nil)
}

// MCPGatewayTool is a tool a server listed through the gateway.
type MCPGatewayTool struct {
	Name       string    `json:"name"`
	Risk       string    `json:"risk"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// MCPGatewayServer is one upstream MCP server registered behind the gateway.
// GatewayPath is the path of the address an agent's configuration names
// instead of UpstreamURL. Identity is what the MCP registry decides and
// Approval its decision.
type MCPGatewayServer struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	UpstreamURL    string           `json:"upstream_url"`
	UpstreamHost   string           `json:"upstream_host"`
	GatewayPath    string           `json:"gateway_path"`
	Identity       string           `json:"identity"`
	Approval       string           `json:"approval"`
	Enabled        bool             `json:"enabled"`
	AllowedTools   []string         `json:"allowed_tools"`
	DeniedTools    []string         `json:"denied_tools"`
	Tools          []MCPGatewayTool `json:"tools"`
	ToolCount      int              `json:"tool_count"`
	LastActivityAt *time.Time       `json:"last_activity_at"`
	Version        int64            `json:"version"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

func validGatewayToolNames(names []string) bool {
	if names == nil || len(names) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !hostedgateway.ValidIdentifier(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

func validMCPGatewayServer(server MCPGatewayServer) bool {
	host, validURL := hostedgateway.ValidUpstreamURL(server.UpstreamURL)
	if !validProductID(server.ID) || !printableInventoryString(server.Name, 1, 128, false) || !validURL || host != server.UpstreamHost || server.Identity != "host:"+server.UpstreamHost ||
		!stringIn(server.Approval, "approved", "unapproved", "blocked") || !validGatewayToolNames(server.AllowedTools) || !validGatewayToolNames(server.DeniedTools) || server.Tools == nil || len(server.Tools) > 64 ||
		server.ToolCount < len(server.Tools) || server.Version < 1 || server.Version > 1000000 || server.CreatedAt.IsZero() || server.UpdatedAt.Before(server.CreatedAt) {
		return false
	}
	for _, tool := range server.Tools {
		if !hostedgateway.ValidIdentifier(tool.Name) || !stringIn(tool.Risk, "execute", "write", "network", "read", "unclassified") || tool.LastSeenAt.IsZero() {
			return false
		}
	}
	return true
}

func decodeMCPGatewayServer(raw json.RawMessage) (MCPGatewayServer, bool) {
	var server MCPGatewayServer
	if decodeStrictDiscovery(raw, &server) != nil || server.GatewayPath != "" {
		return MCPGatewayServer{}, false
	}
	server.GatewayPath = hostedGatewayMCPPrefix + server.ID
	return server, validMCPGatewayServer(server)
}

func (handler *hostedGatewayHandler) listServers(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !gatewayManagementCredential(identity) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	o, w, e := gatewayScope(identity)
	raw, err := handler.database.QueryJSON(request.Context(), currentGatewayServerPageSQL, o, w, e)
	if err != nil {
		writeProductionError(writer, request, discoveryProviderError(err))
		return
	}
	var envelope struct {
		Items []json.RawMessage `json:"items"`
	}
	if !exactJSONFields(raw, "items") || decodeStrictDiscovery(raw, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > 200 {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	servers := make([]MCPGatewayServer, 0, len(envelope.Items))
	for _, item := range envelope.Items {
		server, valid := decodeMCPGatewayServer(item)
		if !valid {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		servers = append(servers, server)
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": servers, "gateway_enabled": handler.gateway != nil}, nil)
}

func (handler *hostedGatewayHandler) putServer(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, id string) {
	_, expectedVersion, valid := discoveryMutationHeaders(request, true)
	var input struct {
		Name         *string   `json:"name"`
		UpstreamURL  *string   `json:"upstream_url"`
		Enabled      *bool     `json:"enabled"`
		AllowedTools *[]string `json:"allowed_tools"`
		DeniedTools  *[]string `json:"denied_tools"`
	}
	if request.Method != http.MethodPut || request.URL.RawQuery != "" || !valid || !validProductID(id) || !gatewayManagementCredential(identity) || decodeProductionJSON(request, &input) != nil ||
		input.Name == nil || input.UpstreamURL == nil || input.Enabled == nil || input.AllowedTools == nil || input.DeniedTools == nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	// The address must be a public https address by its form; that it
	// resolves to public addresses is checked at every connection.
	if _, validURL := hostedgateway.ValidUpstreamURL(*input.UpstreamURL); !validURL || !printableInventoryString(*input.Name, 1, 128, false) || !validGatewayToolNames(*input.AllowedTools) || !validGatewayToolNames(*input.DeniedTools) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	for _, name := range *input.AllowedTools {
		for _, denied := range *input.DeniedTools {
			if name == denied {
				writeProductionError(writer, request, ErrRepositoryOperation)
				return
			}
		}
	}
	allowed, denied := append([]string(nil), *input.AllowedTools...), append([]string(nil), *input.DeniedTools...)
	sort.Strings(allowed)
	sort.Strings(denied)
	payload, err := json.Marshal(map[string]any{"name": *input.Name, "upstream_url": *input.UpstreamURL, "enabled": *input.Enabled, "allowed_tools": append([]string{}, allowed...), "denied_tools": append([]string{}, denied...)})
	auditID, correlationID, ids := handler.mutationIDs(request)
	if err != nil || !ids {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	o, w, e := gatewayScope(identity)
	raw, err := handler.database.QueryJSON(request.Context(), currentGatewayServerPutSQL, o, w, e, identity.PrincipalID.String(), id, json.RawMessage(payload), expectedVersion, auditID, correlationID)
	if err != nil {
		writeProductionError(writer, request, discoveryProviderError(err))
		return
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || string(envelope["audit_id"]) != strconv.Quote(auditID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	delete(envelope, "audit_id")
	delete(envelope, "correlation_id")
	stripped, _ := json.Marshal(envelope)
	server, decoded := decodeMCPGatewayServer(stripped)
	if !decoded || server.ID != id || server.Version != expectedVersion+1 || server.Name != *input.Name || server.UpstreamURL != *input.UpstreamURL {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeDiscoveryMutationHeaders(writer, server.Version, auditID, "")
	status := http.StatusOK
	if expectedVersion == 0 {
		status = http.StatusCreated
	}
	writeJSONValue(writer, request, status, server, nil)
}

func (handler *hostedGatewayHandler) deleteServer(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, id string) {
	_, expectedVersion, valid := discoveryMutationHeaders(request, false)
	if request.Method != http.MethodDelete || request.URL.RawQuery != "" || !valid || !validProductID(id) || !gatewayManagementCredential(identity) || request.ContentLength > 0 {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	auditID, correlationID, ids := handler.mutationIDs(request)
	if !ids {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	o, w, e := gatewayScope(identity)
	raw, err := handler.database.QueryJSON(request.Context(), currentGatewayServerDeleteSQL, o, w, e, identity.PrincipalID.String(), id, expectedVersion, auditID, correlationID)
	if err != nil {
		writeProductionError(writer, request, discoveryProviderError(err))
		return
	}
	var result struct {
		ID            string `json:"id"`
		Deleted       bool   `json:"deleted"`
		AuditID       string `json:"audit_id"`
		CorrelationID string `json:"correlation_id"`
	}
	if !exactJSONFields(raw, "audit_id", "correlation_id", "deleted", "id") || decodeStrictDiscovery(raw, &result) != nil || result.ID != id || !result.Deleted || result.AuditID != auditID {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writer.Header().Set("X-Audit-ID", auditID)
	writer.WriteHeader(http.StatusNoContent)
}

// GatewayDecision is one decision record of the gateway.
type GatewayDecision struct {
	ID            string                 `json:"id"`
	CreatedAt     time.Time              `json:"created_at"`
	Surface       string                 `json:"surface"`
	Operation     string                 `json:"operation"`
	Direction     string                 `json:"direction"`
	Decision      string                 `json:"decision"`
	Reason        string                 `json:"reason"`
	Rules         []GuardrailMatchedRule `json:"rules"`
	Bytes         int64                  `json:"bytes"`
	ContentDigest string                 `json:"content_digest"`
	ServerID      *string                `json:"server_id"`
	ServerName    *string                `json:"server_name"`
	ToolName      *string                `json:"tool_name"`
	Provider      *string                `json:"provider"`
	Model         *string                `json:"model"`
	AgentID       *string                `json:"agent_id"`
	PrincipalID   string                 `json:"principal_id"`
}

func validGatewayDecision(decision GatewayDecision) bool {
	if !validProductID(decision.ID) || decision.CreatedAt.IsZero() || !stringIn(decision.Surface, hostedgateway.SurfaceMCP, hostedgateway.SurfaceLLM) || decision.Operation == "" || len(decision.Operation) > 64 ||
		!stringIn(decision.Direction, hostedgateway.DirectionRequest, hostedgateway.DirectionResponse) || !stringIn(decision.Decision, guardrail.DecisionAllow, guardrail.DecisionRedact, guardrail.DecisionBlock) ||
		!stringIn(decision.Reason, hostedgateway.ReasonNone, hostedgateway.ReasonGuardrail, hostedgateway.ReasonServerBlocked, hostedgateway.ReasonServerUnapproved, hostedgateway.ReasonServerDisabled, hostedgateway.ReasonToolDenied,
			hostedgateway.ReasonToolNotAllowed, hostedgateway.ReasonToolRiskDenied, hostedgateway.ReasonToolsHidden, hostedgateway.ReasonWindowExceeded) ||
		decision.Rules == nil || len(decision.Rules) > 64 || decision.Bytes < 0 || len(decision.ContentDigest) != 71 || !validProductID(decision.PrincipalID) ||
		(decision.Surface == hostedgateway.SurfaceMCP) != (decision.ServerID != nil) || (decision.Surface == hostedgateway.SurfaceLLM) != (decision.Provider != nil) {
		return false
	}
	for _, rule := range decision.Rules {
		if rule.ID == "" || !stringIn(rule.Category, guardrail.CategoryPromptInjection, guardrail.CategorySensitiveData) || !stringIn(rule.Mode, "block", "redact", "monitor") || rule.Count < 1 {
			return false
		}
	}
	return true
}

func (handler *hostedGatewayHandler) listActivity(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	query := request.URL.Query()
	limit := 50
	single := func(name string) (string, bool) {
		values, present := query[name]
		if !present {
			return "", true
		}
		return values[0], len(values) == 1 && values[0] != ""
	}
	valid := request.Method == http.MethodGet && gatewayManagementCredential(identity)
	for name := range query {
		valid = valid && stringIn(name, "surface", "server_id", "agent_id", "decision", "before", "limit")
	}
	surface, surfaceOK := single("surface")
	server, serverOK := single("server_id")
	agent, agentOK := single("agent_id")
	decision, decisionOK := single("decision")
	before, beforeOK := single("before")
	if value, limitOK := single("limit"); !limitOK {
		valid = false
	} else if value != "" {
		parsed, err := strconv.Atoi(value)
		valid = valid && err == nil && parsed >= 1 && parsed <= 100 && strconv.Itoa(parsed) == value
		limit = parsed
	}
	if !valid || !surfaceOK || !serverOK || !agentOK || !decisionOK || !beforeOK || surface != "" && !stringIn(surface, "mcp", "llm") || decision != "" && !stringIn(decision, "allow", "redact", "block") ||
		server != "" && !validProductID(server) || before != "" && !validProductID(before) || agent != "" && !hostedgateway.ValidIdentifier(agent) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	o, w, e := gatewayScope(identity)
	raw, err := handler.database.QueryJSON(request.Context(), currentGatewayActivitySQL, o, w, e, surface, server, agent, decision, before, limit)
	if err != nil {
		writeProductionError(writer, request, discoveryProviderError(err))
		return
	}
	var page struct {
		Items  []GatewayDecision `json:"items"`
		NextID *string           `json:"next_id"`
	}
	if !exactJSONFields(raw, "items", "next_id") || decodeStrictDiscovery(raw, &page) != nil || page.Items == nil || len(page.Items) > limit || page.NextID != nil && (len(page.Items) != limit || page.Items[len(page.Items)-1].ID != *page.NextID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	for _, item := range page.Items {
		if !validGatewayDecision(item) {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": page.Items, "next_cursor": page.NextID}, nil)
}

// hostedGatewayStatementAllowed admits the gateway's statements for the
// checked request they belong to. PostgreSQL compares the same values with
// the attested proof.
func hostedGatewayStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	var operations []string
	var count int
	actor, traffic, pathID := false, false, -1
	switch q {
	case currentGatewayOpenSQL:
		count, actor, traffic = 6, true, true
	case currentGatewayRecordSQL:
		count, actor, traffic = 7, true, true
	case currentGatewayPolicySQL:
		operations, count = []string{"getGatewayPolicy"}, 3
	case currentGatewaySetPolicySQL:
		operations, count, actor = []string{"putGatewayPolicy"}, 8, true
	case currentGatewayServerPageSQL:
		operations, count = []string{"listMCPGatewayServers"}, 3
	case currentGatewayServerPutSQL:
		operations, count, actor, pathID = []string{"putMCPGatewayServer"}, 9, true, 4
	case currentGatewayServerDeleteSQL:
		operations, count, actor, pathID = []string{"deleteMCPGatewayServer"}, 8, true, 4
	case currentGatewayActivitySQL:
		operations, count = []string{"listGatewayActivity"}, 9
	default:
		return false, false
	}
	bearer, browser := g.Identity.CredentialKind == CredentialBearerToken, g.Identity.CredentialKind == CredentialBrowserSession
	if traffic {
		operations = []string{"callMCPGateway", "closeMCPGatewaySession", "createGatewayChatCompletion", "createGatewayResponse", "createGatewayMessage"}
	}
	if !stringIn(g.OperationID, operations...) || g.Collection || len(args) != count || !bearer && (!browser || traffic) {
		return true, false
	}
	e := g.Identity.Scope.EnvironmentID().String()
	expected := []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), e}
	if actor {
		expected = append(expected, g.Identity.PrincipalID.String())
	}
	for index, want := range expected {
		value, ok := args[index].(string)
		if !ok || value == "" || value != want {
			return true, false
		}
	}
	if pathID >= 0 {
		if value, ok := args[pathID].(string); !ok || value == "" || value != g.PathParameters["id"] {
			return true, false
		}
	}
	if traffic {
		// The statement names the request's own operation, and the server
		// of the request path (none for a model request).
		operation, operationOK := args[4].(string)
		server, serverOK := args[5].(string)
		mcp := stringIn(g.OperationID, "callMCPGateway", "closeMCPGatewaySession")
		if !operationOK || operation != g.OperationID || !serverOK || mcp && (server == "" || server != g.PathParameters["id"]) || !mcp && server != "" {
			return true, false
		}
		if q == currentGatewayRecordSQL {
			// The batch has a closed shape with no member for any text.
			raw, ok := args[6].(json.RawMessage)
			var batch gatewayRecordBatch
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if !ok || len(raw) > 131072 || decoder.Decode(&batch) != nil || decoder.More() || len(batch.Records) > 8 || len(batch.Tools) > 256 {
				return true, false
			}
			for _, record := range batch.Records {
				if !validProductID(record.ID) || record.Bytes < 0 || len(record.ContentDigest) != 71 {
					return true, false
				}
			}
		}
	}
	return true, authorizationNativeTargetAllowed(g, "environment", e)
}
