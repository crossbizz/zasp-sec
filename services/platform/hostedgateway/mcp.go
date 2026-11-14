package hostedgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/guardrail"
)

// The hosted MCP gateway speaks the Streamable HTTP transport of the Model
// Context Protocol to the agent and to the upstream server.
//
// DOCUMENTED: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
// (read from the specification's source,
// https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/transports.mdx):
//   - every client message is one HTTP POST whose body is a single JSON-RPC
//     request, notification or response (no batches);
//   - the client's Accept lists application/json and text/event-stream; the
//     answer to a request is one JSON object or a stream of server-sent
//     events that ends with the response; a notification or a response is
//     answered 202 Accepted with no body;
//   - a server may name a session in the MCP-Session-Id header of the
//     initialize result; the client repeats it on every later request, ends
//     the session with HTTP DELETE, and starts again after a 404;
//   - the client sends MCP-Protocol-Version after initialization;
//   - GET opens a stream for messages the server starts; a server that offers
//     none answers 405.
//
// DOCUMENTED: .../docs/specification/2026-07-28/basic/transports/streamable-http.mdx:
// the revision without sessions adds the request headers Mcp-Method, Mcp-Name
// and Mcp-Param-{Name}, which the gateway forwards; GET and DELETE answer 405.
//
// DOCUMENTED: .../docs/specification/2025-11-25/server/tools.mdx: tools/list
// returns result.tools[] (name, description, inputSchema, ...) and
// nextCursor; tools/call takes params.name and params.arguments and returns
// result.content[] (text, image, audio, resource_link, resource),
// structuredContent and isError; a failed execution is a result with
// isError true, which the model is shown.
//
// DOCUMENTED: .../docs/specification/2025-11-25/basic/authorization.mdx: an
// MCP server "MUST NOT pass through the token it received from the MCP
// client". The gateway does not: the platform token in Authorization
// authenticates the agent to the gateway and stays here; the upstream's own
// credential arrives in X-Zasp-Upstream-Authorization and is the only
// credential sent upstream.
//
// The gateway does not open the GET stream (it answers 405, which the
// transport allows), so messages a server starts outside a request are not
// delivered.

// Request headers of the gateway.
const (
	// HeaderUpstreamAuthorization carries the upstream's credential. Its
	// value is sent to the upstream as Authorization (for a model provider:
	// in the provider's own key header). It is never stored or logged.
	HeaderUpstreamAuthorization = "X-Zasp-Upstream-Authorization"
	// HeaderAgentID names the calling agent in the decision records.
	HeaderAgentID = "X-Zasp-Agent-Id"
)

// ReasonToolsHidden is the reason of a tools/list answer the policy removed
// tools from.
const ReasonToolsHidden = "tools_hidden"

// JSON-RPC error code of a refusal by the gateway (the range the JSON-RPC
// specification leaves to the implementation).
const rpcRefused = -32001

// Gateway serves the hosted MCP gateway and the hosted model proxy.
type Gateway struct {
	Client  *http.Client
	Limiter *RateLimiter
	// Timeout bounds one exchange, a stream included.
	Timeout time.Duration
	// MaxResponseBytes bounds one upstream answer that is not a stream, and
	// one event of a stream.
	MaxResponseBytes int
	// AllowUpstreamURL decides whether a registered upstream address is
	// forwarded to. Nil means ValidUpstreamURL.
	AllowUpstreamURL func(string) bool
	// Providers are the model providers the proxy forwards to.
	Providers map[string]Provider
	// RecordFailures counts decisions that could not be recorded after
	// their answer was already on its way (a stream).
	RecordFailures atomic.Int64
}

// Caller is the authenticated sender of one request.
type Caller struct {
	Store Store
	// TokenKey identifies the API token for the rate limit.
	TokenKey string
}

func (gateway *Gateway) maxResponse() int {
	if gateway.MaxResponseBytes > 0 {
		return gateway.MaxResponseBytes
	}
	return 8 << 20
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (message rpcMessage) hasID() bool {
	return len(message.ID) > 0 && string(message.ID) != "null"
}

// parseRPC reads one JSON-RPC 2.0 message. A batch (an array) is refused:
// the transport takes one message for each POST.
func parseRPC(raw []byte) (rpcMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return rpcMessage{}, false
	}
	var message rpcMessage
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	if decoder.Decode(&message) != nil || decoder.More() || message.JSONRPC != "2.0" {
		return rpcMessage{}, false
	}
	if len(message.ID) > 0 {
		// An identifier is a string or a number.
		if first := message.ID[0]; first != '"' && first != '-' && (first < '0' || first > '9') && string(message.ID) != "null" {
			return rpcMessage{}, false
		}
	}
	if message.Method == "" && message.Result == nil && message.Error == nil {
		return rpcMessage{}, false
	}
	if message.Method != "" && (message.Result != nil || message.Error != nil) {
		return rpcMessage{}, false
	}
	return message, true
}

func decodeAny(raw []byte) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.More() {
		return nil, false
	}
	return value, true
}

func encodeJSON(value any) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return nil
	}
	return bytes.TrimRight(buffer.Bytes(), "\n")
}

// Members whose string value is text a model reads.
var textMembers = map[string]bool{"text": true, "instructions": true, "description": true}

// inspectValue passes the strings of a JSON value through the inspection and
// returns the value with what may be forwarded in their place. With all set
// every string is inspected; otherwise only the members a model reads as
// text, and everything under structuredContent. It stops at a block.
func inspectValue(value any, inspection *Inspection, all bool) any {
	if inspection.Blocked() {
		return value
	}
	switch typed := value.(type) {
	case string:
		if all {
			if out, ok := inspection.Text(typed); ok {
				return out
			}
		}
		return typed
	case []any:
		for index := range typed {
			typed[index] = inspectValue(typed[index], inspection, all)
		}
		return typed
	case map[string]any:
		for name, member := range typed {
			if text, isString := member.(string); isString {
				if all || textMembers[name] {
					if out, ok := inspection.Text(text); ok {
						typed[name] = out
					}
				}
				continue
			}
			typed[name] = inspectValue(member, inspection, all || name == "structuredContent")
		}
		return typed
	}
	return value
}

func writeRPC(writer http.ResponseWriter, status int, message rpcMessage) {
	message.JSONRPC = "2.0"
	if message.ID == nil {
		message.ID = json.RawMessage("null")
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encodeJSON(message), '\n'))
}

func rpcError(code int, message string) json.RawMessage {
	return encodeJSON(map[string]any{"code": code, "message": message})
}

// toolRefusal is the result of a tool call the gateway refuses: a failed
// tool call, which the model is shown. A result of the 2026-07-28 revision
// says what kind of result it is, and a client of that revision requires it.
//
// DOCUMENTED: the MCP Python SDK 2.3.0 (mcp_types): "resultType" tags a
// result as "complete" or "input_required" in the 2026-07-28 revision. A
// client of the SDK in that revision refused the gateway's result without
// it; TestRealMCPClientAndServerThroughTheGateway runs that client.
func toolRefusal(message string, modern bool) json.RawMessage {
	result := map[string]any{"content": []any{map[string]any{"type": "text", "text": message}}, "isError": true}
	if modern {
		result["resultType"] = "complete"
	}
	return encodeJSON(result)
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// toolRefusalReason says why the policy refuses a tool, or "".
func toolRefusalReason(session Session, name string) string {
	server := session.Server
	switch {
	case contains(server.DeniedTools, name):
		return ReasonToolDenied
	case len(server.AllowedTools) > 0 && !contains(server.AllowedTools, name):
		return ReasonToolNotAllowed
	case contains(session.Policy.DeniedToolRisks, agentsignals.MCPToolRisk(name)):
		return ReasonToolRiskDenied
	}
	return ""
}

func refusalText(reason string) string {
	switch reason {
	case ReasonServerBlocked:
		return "This MCP server is blocked in the MCP registry of the Environment."
	case ReasonServerUnapproved:
		return "This MCP server is not approved in the MCP registry of the Environment, and the gateway policy refuses unapproved servers."
	case ReasonServerDisabled:
		return "This MCP server is disabled at the gateway."
	case ReasonToolDenied:
		return "Blocked by the gateway: this tool is on the server's deny list."
	case ReasonToolNotAllowed:
		return "Blocked by the gateway: this tool is not on the server's allow list."
	case ReasonToolRiskDenied:
		return "Blocked by the gateway: the gateway policy denies tools of this risk class."
	case ReasonWindowExceeded:
		return "Blocked by the gateway: the content could not be inspected within the gateway's window."
	}
	return "Blocked by the gateway: the content matched a guardrail rule in block mode."
}

// mcpExchange is the state of one request through the gateway.
type mcpExchange struct {
	session  Session
	method   string
	id       json.RawMessage
	toolName string
	agentID  string
	// modern says the request is of the 2026-07-28 revision or later: it
	// carries the Mcp-Method header that revision requires.
	modern   bool
	request  *Inspection
	response *Inspection
	tools    []ToolSeen
	hidden   int
	records  []Record
}

func (exchange *mcpExchange) record(direction string, verdict Verdict) {
	exchange.records = append(exchange.records, Record{Surface: SurfaceMCP, Operation: exchange.operation(), Direction: direction, Decision: verdict.Decision, Reason: verdict.Reason,
		Rules: verdict.Rules, Bytes: verdict.Bytes, Digest: verdict.Digest, ToolName: recordable(exchange.toolName), AgentID: exchange.agentID})
}

// operation is the method as it is recorded: a method of the protocol, or
// "other" for one the gateway only forwards.
func (exchange *mcpExchange) operation() string {
	switch exchange.method {
	case "initialize", "ping", "tools/list", "tools/call", "resources/list", "resources/read", "resources/templates/list", "prompts/list", "prompts/get", "completion/complete", "logging/setLevel", "session/close":
		return exchange.method
	}
	if strings.HasPrefix(exchange.method, "notifications/") {
		return "notification"
	}
	if exchange.method == "" {
		return "response"
	}
	return "other"
}

// absorb adds what a side inspection found to the response's. A side
// inspection that blocked means its content was withheld, which changes the
// answer.
func (exchange *mcpExchange) absorb(side *Inspection) {
	for rule, count := range side.counts {
		exchange.response.counts[rule] += count
	}
	if side.blocked || side.redacted {
		exchange.response.redacted = true
	}
}

// rewriteResponse applies the policy to the upstream's answer.
func (exchange *mcpExchange) rewriteResponse(message *rpcMessage) {
	inspection := exchange.response
	if message.Error != nil {
		value, ok := decodeAny(message.Error)
		if !ok {
			message.Error = rpcError(rpcRefused, "The upstream MCP server returned a malformed error.")
			return
		}
		value = inspectValue(value, inspection, true)
		if inspection.Blocked() {
			message.Error = rpcError(rpcRefused, refusalText(inspection.Verdict().Reason))
		} else if inspection.Redacted() {
			message.Error = encodeJSON(value)
		}
		return
	}
	value, ok := decodeAny(message.Result)
	if !ok {
		message.Result, message.Error = nil, rpcError(rpcRefused, "The upstream MCP server returned a malformed result.")
		return
	}
	if exchange.method == "tools/list" {
		if result, isObject := value.(map[string]any); isObject {
			if listed, isList := result["tools"].([]any); isList {
				result["tools"] = exchange.filterTools(listed)
				if exchange.hidden > 0 || inspection.Redacted() {
					inspection.redacted = true
					message.Result = encodeJSON(result)
				}
			}
		}
		return
	}
	value = inspectValue(value, inspection, false)
	switch {
	case inspection.Blocked() && exchange.method == "tools/call":
		// The model is shown a failed tool call, as for any tool error.
		message.Result = toolRefusal(refusalText(inspection.Verdict().Reason), exchange.modern)
	case inspection.Blocked():
		message.Result, message.Error = nil, rpcError(rpcRefused, refusalText(inspection.Verdict().Reason))
	case inspection.Redacted():
		message.Result = encodeJSON(value)
	}
}

// filterTools removes the tools the policy hides: a denied tool, a tool that
// is not on a non-empty allow list, a tool of a denied risk class, and a tool
// whose description matches a guardrail rule in block mode (an instruction
// planted in a description reaches the model with the tool list). Every tool
// with a recordable name is noted for the inventory, hidden or not.
func (exchange *mcpExchange) filterTools(listed []any) []any {
	kept := make([]any, 0, len(listed))
	for _, entry := range listed {
		tool, isObject := entry.(map[string]any)
		name, _ := tool["name"].(string)
		if !isObject || name == "" {
			exchange.hidden++
			continue
		}
		if agentsignals.ValidMCPToolName(name) && len(exchange.tools) < 256 {
			exchange.tools = append(exchange.tools, ToolSeen{Name: name, Risk: agentsignals.MCPToolRisk(name)})
		}
		if toolRefusalReason(exchange.session, name) != "" {
			exchange.hidden++
			continue
		}
		side := NewInspection(exchange.session.Guardrail, guardrail.DirectionInput)
		for _, member := range []string{"description", "title"} {
			if text, isString := tool[member].(string); isString {
				if out, ok := side.Text(text); ok {
					tool[member] = out
				}
			}
		}
		exchange.absorb(side)
		if side.Blocked() {
			exchange.hidden++
			continue
		}
		kept = append(kept, tool)
	}
	return kept
}

// ServeMCP handles one POST to a gateway server: one JSON-RPC message of the
// agent, forwarded to the registered upstream under the Environment's policy.
func (gateway *Gateway) ServeMCP(writer http.ResponseWriter, request *http.Request, caller Caller, serverID string, body []byte) {
	writer.Header().Set("Cache-Control", "no-store")
	message, ok := parseRPC(body)
	if !ok {
		writeRPC(writer, http.StatusBadRequest, rpcMessage{Error: rpcError(-32600, "The body must be a single JSON-RPC 2.0 message.")})
		return
	}
	ctx, cancel := boundedContext(request.Context(), gateway.Timeout)
	defer cancel()
	session, err := caller.Store.Open(ctx, serverID)
	if err != nil || session.Server == nil {
		gateway.writeStoreError(writer, message.ID, err)
		return
	}
	if !gateway.Limiter.Allow(caller.TokenKey, session.Policy.RequestsPerMinute) {
		writer.Header().Set("Retry-After", "1")
		writeRPC(writer, http.StatusTooManyRequests, rpcMessage{ID: message.ID, Error: rpcError(rpcRefused, "The gateway's rate limit for this token is exceeded.")})
		return
	}
	exchange := &mcpExchange{session: session, method: message.Method, id: message.ID, agentID: recordable(request.Header.Get(HeaderAgentID)), modern: request.Header.Get("Mcp-Method") != "",
		request: NewInspection(session.Guardrail, guardrail.DirectionOutput), response: NewInspection(session.Guardrail, guardrail.DirectionInput)}
	exchange.request.Observe(body)
	defer gateway.lateMCP(ctx, caller, serverID, exchange)

	// The server itself.
	reason := ""
	switch {
	case !session.Server.Enabled:
		reason = ReasonServerDisabled
	case session.Server.Approval == "blocked":
		reason = ReasonServerBlocked
	case session.Server.Approval != "approved" && session.Policy.UnapprovedServers != "allow":
		reason = ReasonServerUnapproved
	}
	if reason != "" {
		verdict := exchange.request.Verdict()
		verdict.Decision, verdict.Reason = guardrail.DecisionBlock, reason
		exchange.record(DirectionRequest, verdict)
		if !gateway.recordNow(ctx, writer, caller, serverID, exchange) {
			return
		}
		writeRPC(writer, http.StatusForbidden, rpcMessage{ID: message.ID, Error: rpcError(rpcRefused, refusalText(reason))})
		return
	}

	// A tool call: the tool, then its arguments.
	if message.Method == "tools/call" && message.hasID() {
		var params map[string]json.RawMessage
		if json.Unmarshal(message.Params, &params) != nil || json.Unmarshal(params["name"], &exchange.toolName) != nil || exchange.toolName == "" {
			writeRPC(writer, http.StatusOK, rpcMessage{ID: message.ID, Error: rpcError(-32602, "A tool call names its tool in params.name.")})
			return
		}
		refusal := toolRefusalReason(session, exchange.toolName)
		if refusal == "" && len(params["arguments"]) > 0 {
			arguments, valid := decodeAny(params["arguments"])
			if !valid {
				writeRPC(writer, http.StatusOK, rpcMessage{ID: message.ID, Error: rpcError(-32602, "The arguments of a tool call are a JSON object.")})
				return
			}
			arguments = inspectValue(arguments, exchange.request, true)
			if exchange.request.Redacted() && !exchange.request.Blocked() {
				// The Mcp-Param-* headers of the 2026-07-28 revision repeat
				// argument values; the upstream refuses a request whose
				// headers and body disagree, and a header is not rewritten.
				for name := range request.Header {
					if strings.HasPrefix(http.CanonicalHeaderKey(name), "Mcp-Param-") {
						exchange.request.Block()
					}
				}
				params["arguments"] = encodeJSON(arguments)
				message.Params = encodeJSON(params)
				body = encodeJSON(message)
			}
		}
		verdict := exchange.request.Verdict()
		if refusal != "" {
			verdict.Decision, verdict.Reason = guardrail.DecisionBlock, refusal
		}
		exchange.record(DirectionRequest, verdict)
		if verdict.Decision == guardrail.DecisionBlock {
			if !gateway.recordNow(ctx, writer, caller, serverID, exchange) {
				return
			}
			writeRPC(writer, http.StatusOK, rpcMessage{ID: message.ID, Result: toolRefusal(refusalText(verdict.Reason), exchange.modern)})
			return
		}
	}

	response, err := gateway.forwardMCP(ctx, request, http.MethodPost, session.Server.UpstreamURL, body)
	if err != nil {
		gateway.writeUpstreamError(writer, message.ID, err)
		return
	}
	defer response.Body.Close()
	for _, name := range []string{"Mcp-Session-Id", "Mcp-Protocol-Version"} {
		if value := response.Header.Get(name); value != "" && len(value) <= 512 {
			writer.Header().Set(name, value)
		}
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(response.Header.Get("Content-Type"), ";", 2)[0]))
	switch {
	case response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusNoContent:
		if !gateway.recordNow(ctx, writer, caller, serverID, exchange) {
			return
		}
		writer.WriteHeader(http.StatusAccepted)
	case response.StatusCode == http.StatusOK && mediaType == "text/event-stream" && message.hasID():
		gateway.streamMCP(ctx, writer, response, caller, serverID, exchange)
	case response.StatusCode == http.StatusOK && mediaType == "application/json" && message.hasID():
		raw, err := readBounded(response.Body, gateway.maxResponse())
		answer, parsed := parseRPC(raw)
		if err != nil || !parsed || answer.Method != "" {
			writeRPC(writer, http.StatusBadGateway, rpcMessage{ID: message.ID, Error: rpcError(rpcRefused, "The upstream MCP server's answer was not a JSON-RPC response within the gateway's size limit.")})
			return
		}
		exchange.response.Observe(raw)
		exchange.rewriteResponse(&answer)
		exchange.finish()
		if !gateway.recordNow(ctx, writer, caller, serverID, exchange) {
			return
		}
		writeRPC(writer, http.StatusOK, answer)
	default:
		gateway.writeUpstreamStatus(ctx, writer, response, caller, serverID, exchange)
	}
}

// finish adds the response's record when the method's answer is recorded: a
// tool call and a tool list always, any other method when something was
// redacted or blocked.
func (exchange *mcpExchange) finish() {
	verdict := exchange.response.Verdict()
	if exchange.method == "tools/list" && exchange.hidden > 0 && verdict.Decision == guardrail.DecisionRedact && len(verdict.Rules) == 0 {
		verdict.Reason = ReasonToolsHidden
	}
	if exchange.method == "tools/call" || exchange.method == "tools/list" || verdict.Decision != guardrail.DecisionAllow {
		exchange.record(DirectionResponse, verdict)
	}
}

// recordNow writes the exchange's records before the answer is sent. When
// they cannot be written the answer is not sent.
func (gateway *Gateway) recordNow(ctx context.Context, writer http.ResponseWriter, caller Caller, serverID string, exchange *mcpExchange) bool {
	if len(exchange.records) == 0 && len(exchange.tools) == 0 {
		return true
	}
	if err := caller.Store.Record(ctx, serverID, exchange.records, exchange.tools); err != nil {
		writeRPC(writer, http.StatusServiceUnavailable, rpcMessage{ID: exchange.id, Error: rpcError(rpcRefused, "The gateway could not record its decision; nothing was returned.")})
		return false
	}
	exchange.records, exchange.tools = nil, nil
	return true
}

// streamMCP relays a stream of server-sent events. Each event is one
// JSON-RPC message: the response to the request (which ends the stream), or
// a notification or request of the server that belongs to it.
func (gateway *Gateway) streamMCP(ctx context.Context, writer http.ResponseWriter, response *http.Response, caller Caller, serverID string, exchange *mcpExchange) {
	reader := newSSEReader(response.Body, gateway.maxResponse(), exchange.response.Observe)
	sseHeaders(writer.Header())
	writer.WriteHeader(http.StatusOK)
	out := newSSEWriter(writer)
	answered := false
	for !answered {
		event, err := reader.Next()
		if err != nil {
			break
		}
		if !event.HasData || strings.TrimSpace(event.Data) == "" {
			// The priming event and retry hints carry no message.
			if out.Write(event) != nil {
				break
			}
			continue
		}
		message, parsed := parseRPC([]byte(event.Data))
		if !parsed {
			continue
		}
		if message.Method != "" {
			// A message the server starts: every string of it is inspected
			// on its own; one that must not be forwarded is dropped.
			side := NewInspection(exchange.session.Guardrail, guardrail.DirectionInput)
			if len(message.Params) > 0 {
				params, valid := decodeAny(message.Params)
				if !valid {
					continue
				}
				params = inspectValue(params, side, true)
				if side.Redacted() {
					message.Params = encodeJSON(params)
				}
			}
			exchange.absorb(side)
			if side.Blocked() {
				continue
			}
		} else {
			exchange.rewriteResponse(&message)
			answered = true
		}
		message.JSONRPC = "2.0"
		event.Data = string(encodeJSON(message))
		if out.Write(event) != nil {
			break
		}
	}
	exchange.finish()
}

// lateMCP writes what an exchange still has to record when its answer did
// not wait for the record: a stream that is already with the agent, or an
// answer that is an error of the upstream. It has its own deadline, and a
// failure is counted.
func (gateway *Gateway) lateMCP(ctx context.Context, caller Caller, serverID string, exchange *mcpExchange) {
	if len(exchange.records) == 0 && len(exchange.tools) == 0 {
		return
	}
	late, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if caller.Store.Record(late, serverID, exchange.records, exchange.tools) != nil {
		gateway.RecordFailures.Add(1)
	}
	exchange.records, exchange.tools = nil, nil
}

// writeUpstreamStatus answers for an upstream status that is not a result.
func (gateway *Gateway) writeUpstreamStatus(ctx context.Context, writer http.ResponseWriter, response *http.Response, caller Caller, serverID string, exchange *mcpExchange) {
	raw, _ := readBounded(response.Body, 64<<10)
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		writeRPC(writer, http.StatusBadGateway, rpcMessage{ID: exchange.id, Error: rpcError(rpcRefused, "The upstream MCP server refused the credential sent in "+HeaderUpstreamAuthorization+".")})
		return
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable:
		// A status of the transport (an ended session is 404, an unknown
		// protocol version 400): the agent is told the same, with the
		// upstream's JSON-RPC error when it sent one.
		if answer, parsed := parseRPC(raw); parsed && answer.Method == "" && answer.Error != nil {
			exchange.response.Observe(raw)
			exchange.rewriteResponse(&answer)
			exchange.finish()
			if !gateway.recordNow(ctx, writer, caller, serverID, exchange) {
				return
			}
			writeRPC(writer, response.StatusCode, answer)
			return
		}
		writeRPC(writer, response.StatusCode, rpcMessage{ID: exchange.id, Error: rpcError(rpcRefused, "The upstream MCP server answered HTTP "+http.StatusText(response.StatusCode)+".")})
		return
	}
	writeRPC(writer, http.StatusBadGateway, rpcMessage{ID: exchange.id, Error: rpcError(rpcRefused, "The upstream MCP server gave an answer the gateway does not relay.")})
}

// CloseMCP forwards the end of a session (HTTP DELETE) to the upstream.
func (gateway *Gateway) CloseMCP(writer http.ResponseWriter, request *http.Request, caller Caller, serverID string) {
	writer.Header().Set("Cache-Control", "no-store")
	ctx, cancel := boundedContext(request.Context(), 30*time.Second)
	defer cancel()
	session, err := caller.Store.Open(ctx, serverID)
	if err != nil || session.Server == nil {
		gateway.writeStoreError(writer, nil, err)
		return
	}
	if !gateway.Limiter.Allow(caller.TokenKey, session.Policy.RequestsPerMinute) {
		writer.Header().Set("Retry-After", "1")
		writeRPC(writer, http.StatusTooManyRequests, rpcMessage{Error: rpcError(rpcRefused, "The gateway's rate limit for this token is exceeded.")})
		return
	}
	if request.Header.Get("Mcp-Session-Id") == "" {
		writeRPC(writer, http.StatusBadRequest, rpcMessage{Error: rpcError(-32600, "Ending a session names it in MCP-Session-Id.")})
		return
	}
	response, err := gateway.forwardMCP(ctx, request, http.MethodDelete, session.Server.UpstreamURL, nil)
	if err != nil {
		gateway.writeUpstreamError(writer, nil, err)
		return
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	switch response.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusBadRequest:
		writer.WriteHeader(response.StatusCode)
	default:
		writer.WriteHeader(http.StatusBadGateway)
	}
}

// Headers of the agent that are sent on to the upstream MCP server.
var mcpForwardedHeaders = []string{"Accept", "Mcp-Session-Id", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name", "Last-Event-Id"}

func (gateway *Gateway) forwardMCP(ctx context.Context, request *http.Request, method, target string, body []byte) (*http.Response, error) {
	valid := gateway.AllowUpstreamURL
	if valid == nil {
		valid = func(value string) bool { _, ok := ValidUpstreamURL(value); return ok }
	}
	if !valid(target) {
		return nil, ErrUpstreamAddress
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	upstream, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	for _, name := range mcpForwardedHeaders {
		if value := request.Header.Get(name); value != "" {
			upstream.Header.Set(name, value)
		}
	}
	for name, values := range request.Header {
		if canonical := http.CanonicalHeaderKey(name); strings.HasPrefix(canonical, "Mcp-Param-") && len(values) == 1 {
			upstream.Header.Set(canonical, values[0])
		}
	}
	if body != nil {
		upstream.Header.Set("Content-Type", "application/json")
		if upstream.Header.Get("Accept") == "" {
			upstream.Header.Set("Accept", "application/json, text/event-stream")
		}
	}
	if credential := request.Header.Get(HeaderUpstreamAuthorization); credential != "" {
		upstream.Header.Set("Authorization", credential)
	}
	upstream.Header.Set("User-Agent", "zasp-hosted-gateway")
	return gateway.Client.Do(upstream)
}

func (gateway *Gateway) writeStoreError(writer http.ResponseWriter, id json.RawMessage, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeRPC(writer, http.StatusNotFound, rpcMessage{ID: id, Error: rpcError(rpcRefused, "No such gateway server in this Environment.")})
	case errors.Is(err, ErrForbidden):
		writeRPC(writer, http.StatusForbidden, rpcMessage{ID: id, Error: rpcError(rpcRefused, "This token may not use the gateway.")})
	default:
		writeRPC(writer, http.StatusServiceUnavailable, rpcMessage{ID: id, Error: rpcError(rpcRefused, "The gateway's policy is unavailable.")})
	}
}

func (gateway *Gateway) writeUpstreamError(writer http.ResponseWriter, id json.RawMessage, err error) {
	message := "The upstream MCP server could not be reached."
	if errors.Is(err, ErrUpstreamAddress) {
		message = "The upstream MCP server's address is not a public https address."
	} else if errors.Is(err, context.DeadlineExceeded) {
		message = "The upstream MCP server did not answer in time."
	}
	writeRPC(writer, http.StatusBadGateway, rpcMessage{ID: id, Error: rpcError(rpcRefused, message)})
}

var errTooLarge = errors.New("upstream answer too large")

func readBounded(source io.Reader, maximum int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(source, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maximum {
		return nil, errTooLarge
	}
	return raw, nil
}
