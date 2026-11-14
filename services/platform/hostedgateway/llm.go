package hostedgateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/guardrail"
)

// The hosted model proxy. An agent's SDK is pointed at the platform instead
// of at the provider: the base URL changes, the SDK's key becomes a platform
// token, and the provider's own key travels in a header of each request. The
// proxy applies the Environment's guardrail policy to what goes to the model
// and to what comes back, forwards to the provider, and records the two
// decisions without any text.

// The three APIs the proxy speaks.
const (
	APIChatCompletions = "chat.completions"
	APIResponses       = "responses"
	APIMessages        = "messages"
)

// Request headers of the proxy.
const (
	// HeaderUpstreamProvider names the provider of the catalog. Without it a
	// chat completion or a response goes to openai and a message to
	// anthropic.
	HeaderUpstreamProvider = "X-Zasp-Upstream-Provider"
	// HeaderUpstreamHost names the customer's own host of a provider that
	// has one for each customer (an Azure OpenAI resource).
	HeaderUpstreamHost = "X-Zasp-Upstream-Host"
)

// Provider is one model provider the proxy forwards to. The hosts are a
// closed list: a request cannot name an address, only a provider of the
// catalog (and, for a provider with a host for each customer, a host under
// the provider's own domain).
type Provider struct {
	Name string
	// BaseURL is the provider's address and path prefix. For a provider with
	// a host for each customer it is empty, and HostSuffix and BasePath say
	// what a host must end in and what follows it.
	BaseURL    string
	HostSuffix string
	BasePath   string
	// KeyHeader is the header the provider's key is sent in: Authorization
	// (as a bearer token), x-api-key or api-key.
	KeyHeader string
	// Paths maps each API the provider has to its path under the base.
	Paths map[string]string
	// Forward are the request headers passed on unchanged.
	Forward []string
}

// DefaultProviders is the catalog the platform ships.
func DefaultProviders() map[string]Provider {
	return map[string]Provider{
		// DOCUMENTED: https://github.com/openai/openai-openapi (openapi.yaml,
		// branch manual_spec): servers url https://api.openai.com/v1, paths
		// /chat/completions and /responses, bearer authentication.
		"openai": {Name: "openai", BaseURL: "https://api.openai.com/v1", KeyHeader: "Authorization",
			Paths: map[string]string{APIChatCompletions: "/chat/completions", APIResponses: "/responses"}, Forward: []string{"OpenAI-Organization", "OpenAI-Project", "OpenAI-Beta", "Idempotency-Key"}},
		// DOCUMENTED: https://platform.claude.com/docs/en/build-with-claude/streaming
		// and the Messages API examples: POST https://api.anthropic.com/v1/messages
		// with x-api-key and anthropic-version.
		"anthropic": {Name: "anthropic", BaseURL: "https://api.anthropic.com/v1", KeyHeader: "x-api-key",
			Paths: map[string]string{APIMessages: "/messages"}, Forward: []string{"anthropic-version", "anthropic-beta"}},
		// UNVERIFIED: the Azure OpenAI "v1" address form
		// https://<resource>.openai.azure.com/openai/v1/... with the api-key
		// header is written from memory; learn.microsoft.com could not be
		// read from the build environment. It has not been called.
		"azure_openai": {Name: "azure_openai", HostSuffix: ".openai.azure.com", BasePath: "/openai/v1", KeyHeader: "api-key",
			Paths: map[string]string{APIChatCompletions: "/chat/completions", APIResponses: "/responses"}},
	}
}

var providerHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// target resolves the address of one API of the provider.
func (provider Provider) target(api, host string) (string, bool) {
	path, has := provider.Paths[api]
	if !has {
		return "", false
	}
	if provider.BaseURL != "" {
		return provider.BaseURL + path, host == ""
	}
	label := strings.TrimSuffix(host, provider.HostSuffix)
	if provider.HostSuffix == "" || len(host) > 253 || !providerHostPattern.MatchString(host) || !strings.HasSuffix(host, provider.HostSuffix) || label == "" || strings.Contains(label, ".") {
		return "", false
	}
	return "https://" + host + provider.BasePath + path, true
}

// Response headers of a provider that are passed back to the agent.
var llmReturnedHeaders = []string{"Content-Type", "Retry-After", "Request-Id", "X-Request-Id", "Openai-Processing-Ms", "Openai-Version",
	"X-Ratelimit-Limit-Requests", "X-Ratelimit-Limit-Tokens", "X-Ratelimit-Remaining-Requests", "X-Ratelimit-Remaining-Tokens", "X-Ratelimit-Reset-Requests", "X-Ratelimit-Reset-Tokens",
	"Anthropic-Ratelimit-Requests-Limit", "Anthropic-Ratelimit-Requests-Remaining", "Anthropic-Ratelimit-Requests-Reset", "Anthropic-Ratelimit-Tokens-Limit", "Anthropic-Ratelimit-Tokens-Remaining", "Anthropic-Ratelimit-Tokens-Reset"}

func llmErrorBody(api string, status int, code, message string) []byte {
	if api == APIMessages {
		kind := "invalid_request_error"
		switch status {
		case http.StatusForbidden:
			kind = "permission_error"
		case http.StatusTooManyRequests:
			kind = "rate_limit_error"
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			kind = "api_error"
		}
		return encodeJSON(map[string]any{"type": "error", "error": map[string]any{"type": kind, "message": message}})
	}
	kind := "invalid_request_error"
	if status >= 500 {
		kind = "api_error"
	}
	return encodeJSON(map[string]any{"error": map[string]any{"message": message, "type": kind, "param": nil, "code": code}})
}

func writeLLMError(writer http.ResponseWriter, api string, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(llmErrorBody(api, status, code, message), '\n'))
}

// inspectContent inspects the content of a message: a string, or a list of
// parts whose text is in "text". A tool result of the Messages API holds its
// own content, which is inspected the same way.
func inspectContent(content any, inspection *Inspection, trusted bool) any {
	scan := inspection.Text
	if trusted {
		scan = inspection.TrustedText
	}
	switch typed := content.(type) {
	case string:
		if out, ok := scan(typed); ok {
			return out
		}
	case []any:
		for _, entry := range typed {
			part, isObject := entry.(map[string]any)
			if !isObject {
				continue
			}
			if text, isString := part["text"].(string); isString {
				if out, ok := scan(text); ok {
					part["text"] = out
				}
			}
			if part["type"] == "tool_result" {
				part["content"] = inspectContent(part["content"], inspection, trusted)
			}
		}
	}
	return content
}

// inspectLLMRequest inspects what a request sends to the model: the
// messages, the tool results among them, and (for sensitive data only) the
// system prompt, which the operator of the agent wrote.
func inspectLLMRequest(api string, body map[string]any, inspection *Inspection) {
	trustedRole := func(message map[string]any) bool {
		role, _ := message["role"].(string)
		return role == "system" || role == "developer"
	}
	switch api {
	case APIChatCompletions:
		messages, _ := body["messages"].([]any)
		for _, entry := range messages {
			if message, isObject := entry.(map[string]any); isObject && message["content"] != nil {
				message["content"] = inspectContent(message["content"], inspection, trustedRole(message))
			}
		}
	case APIResponses:
		if body["instructions"] != nil {
			body["instructions"] = inspectContent(body["instructions"], inspection, true)
		}
		switch input := body["input"].(type) {
		case string:
			body["input"] = inspectContent(input, inspection, false)
		case []any:
			for _, entry := range input {
				item, isObject := entry.(map[string]any)
				if !isObject {
					continue
				}
				if item["content"] != nil {
					item["content"] = inspectContent(item["content"], inspection, trustedRole(item))
				}
				if item["type"] == "function_call_output" && item["output"] != nil {
					item["output"] = inspectContent(item["output"], inspection, false)
				}
			}
		}
	case APIMessages:
		if body["system"] != nil {
			body["system"] = inspectContent(body["system"], inspection, true)
		}
		messages, _ := body["messages"].([]any)
		for _, entry := range messages {
			if message, isObject := entry.(map[string]any); isObject && message["content"] != nil {
				message["content"] = inspectContent(message["content"], inspection, trustedRole(message))
			}
		}
	}
}

// inspectResponsesItem inspects one output item of the Responses API: the
// text of a message and the arguments of a function call. known gives the
// text a stream already released for a part, so that the item of the final
// events says exactly what the deltas said.
func inspectResponsesItem(item map[string]any, index string, inspection *Inspection, known map[string]*strings.Builder) {
	text := func(key, value string) string {
		if released, has := known[key]; has {
			return released.String()
		}
		if out, ok := inspection.Text(value); ok {
			return out
		}
		return ""
	}
	if parts, isList := item["content"].([]any); isList {
		for position, entry := range parts {
			if part, isObject := entry.(map[string]any); isObject {
				if value, isString := part["text"].(string); isString {
					part["text"] = text("o"+index+"."+itoa(position), value)
				}
			}
		}
	}
	if value, isString := item["arguments"].(string); isString {
		item["arguments"] = text("a"+index, value)
	}
}

// inspectLLMResponse inspects a complete answer of the model: its text and
// the arguments of the tool calls it makes.
func inspectLLMResponse(api string, body map[string]any, inspection *Inspection) {
	switch api {
	case APIChatCompletions:
		choices, _ := body["choices"].([]any)
		for _, entry := range choices {
			choice, _ := entry.(map[string]any)
			message, isObject := choice["message"].(map[string]any)
			if !isObject {
				continue
			}
			if message["content"] != nil {
				message["content"] = inspectContent(message["content"], inspection, false)
			}
			calls, _ := message["tool_calls"].([]any)
			for _, call := range calls {
				function, _ := call.(map[string]any)["function"].(map[string]any)
				if arguments, isString := function["arguments"].(string); isString {
					if out, ok := inspection.Text(arguments); ok {
						function["arguments"] = out
					}
				}
			}
		}
	case APIResponses:
		output, _ := body["output"].([]any)
		for index, entry := range output {
			if item, isObject := entry.(map[string]any); isObject {
				inspectResponsesItem(item, itoa(index), inspection, nil)
			}
		}
	case APIMessages:
		content, _ := body["content"].([]any)
		for _, entry := range content {
			block, isObject := entry.(map[string]any)
			if !isObject {
				continue
			}
			if text, isString := block["text"].(string); isString && block["type"] == "text" {
				if out, ok := inspection.Text(text); ok {
					block["text"] = out
				}
			}
			if block["type"] == "tool_use" && block["input"] != nil {
				block["input"] = inspectValue(block["input"], inspection, true)
			}
		}
	}
}

func itoa(value int) string { return strconv.Itoa(value) }

// ServeLLM handles one request of the model proxy.
func (gateway *Gateway) ServeLLM(writer http.ResponseWriter, request *http.Request, caller Caller, api string, body []byte) {
	writer.Header().Set("Cache-Control", "no-store")
	ctx, cancel := boundedContext(request.Context(), gateway.Timeout)
	defer cancel()
	session, err := caller.Store.Open(ctx, "")
	switch {
	case errors.Is(err, ErrForbidden):
		writeLLMError(writer, api, http.StatusForbidden, "gateway_forbidden", "This token may not use the gateway.")
		return
	case err != nil:
		writeLLMError(writer, api, http.StatusServiceUnavailable, "gateway_unavailable", "The gateway's policy is unavailable.")
		return
	}
	if !gateway.admitted(caller, session) {
		writer.Header().Set("Retry-After", "1")
		writeLLMError(writer, api, http.StatusTooManyRequests, "gateway_rate_limited", "The gateway's rate limit for this token is exceeded.")
		return
	}
	name := request.Header.Get(HeaderUpstreamProvider)
	if name == "" {
		name = "openai"
		if api == APIMessages {
			name = "anthropic"
		}
	}
	provider, known := gateway.Providers[name]
	target, valid := provider.target(api, strings.ToLower(request.Header.Get(HeaderUpstreamHost)))
	if !known || !valid {
		writeLLMError(writer, api, http.StatusBadRequest, "gateway_provider", "The provider named in "+HeaderUpstreamProvider+" is not one the gateway forwards this API to.")
		return
	}
	// The provider's key: the dedicated header, or the header the
	// provider's own SDK sends it in when that is not Authorization (which
	// carries the platform token).
	key := strings.TrimSpace(request.Header.Get(HeaderUpstreamAuthorization))
	if len(key) > 7 && strings.EqualFold(key[:7], "bearer ") {
		key = strings.TrimSpace(key[7:])
	}
	if key == "" && provider.KeyHeader != "Authorization" {
		key = strings.TrimSpace(request.Header.Get(provider.KeyHeader))
	}
	if key == "" || len(key) > 4096 || strings.ContainsAny(key, "\r\n") {
		writeLLMError(writer, api, http.StatusBadRequest, "gateway_upstream_key", "Send the provider's own key in "+HeaderUpstreamAuthorization+".")
		return
	}
	value, parsed := decodeAny(body)
	payload, isObject := value.(map[string]any)
	if !parsed || !isObject {
		writeLLMError(writer, api, http.StatusBadRequest, "gateway_request", "The body must be a JSON object.")
		return
	}
	model, _ := payload["model"].(string)
	exchange := &llmExchange{api: api, provider: provider.Name, model: recordable(model), agentID: recordable(request.Header.Get(HeaderAgentID)),
		request: NewInspection(session.Guardrail, guardrail.DirectionInput), response: NewInspection(session.Guardrail, guardrail.DirectionOutput)}
	exchange.request.Observe(body)
	inspectLLMRequest(api, payload, exchange.request)
	exchange.record(DirectionRequest, exchange.request.Verdict())
	if exchange.request.Blocked() {
		if caller.Store.Record(ctx, "", exchange.records, nil) != nil {
			writeLLMError(writer, api, http.StatusServiceUnavailable, "gateway_unavailable", "The gateway could not record its decision.")
			return
		}
		writeLLMError(writer, api, http.StatusBadRequest, "guardrail_blocked", refusalText(exchange.request.Verdict().Reason))
		return
	}
	if exchange.request.Redacted() {
		body = encodeJSON(payload)
	}

	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		writeLLMError(writer, api, http.StatusBadGateway, "gateway_upstream", "The provider could not be reached.")
		return
	}
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("User-Agent", "zasp-hosted-gateway")
	if accept := request.Header.Get("Accept"); accept != "" {
		upstream.Header.Set("Accept", accept)
	}
	for _, header := range provider.Forward {
		if forwarded := request.Header.Get(header); forwarded != "" {
			upstream.Header.Set(header, forwarded)
		}
	}
	if provider.KeyHeader == "Authorization" {
		upstream.Header.Set("Authorization", "Bearer "+key)
	} else {
		upstream.Header.Set(provider.KeyHeader, key)
	}
	response, err := gateway.Client.Do(upstream)
	if err != nil {
		gateway.recordLate(ctx, caller, exchange.records)
		message := "The provider could not be reached."
		if errors.Is(err, context.DeadlineExceeded) {
			message = "The provider did not answer in time."
		}
		writeLLMError(writer, api, http.StatusBadGateway, "gateway_upstream", message)
		return
	}
	defer response.Body.Close()
	for _, header := range llmReturnedHeaders {
		if returned := response.Header.Get(header); returned != "" && len(returned) <= 1024 {
			writer.Header().Set(header, returned)
		}
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(response.Header.Get("Content-Type"), ";", 2)[0]))
	switch {
	case response.StatusCode != http.StatusOK:
		// The provider's own error, to the caller who sent the request.
		raw, _ := readBounded(response.Body, 1<<20)
		gateway.recordLate(ctx, caller, exchange.records)
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			writer.Header().Del("Content-Type")
			writeLLMError(writer, api, http.StatusBadGateway, "gateway_upstream", "The provider answered with a redirect, which the gateway does not follow.")
			return
		}
		writer.WriteHeader(response.StatusCode)
		_, _ = writer.Write(raw)
	case mediaType == "text/event-stream":
		gateway.streamLLM(ctx, cancel, writer, response, caller, exchange)
	default:
		raw, err := readBounded(response.Body, gateway.maxResponse())
		answer, parsed := decodeAny(raw)
		object, isObject := answer.(map[string]any)
		if err != nil || !parsed || !isObject {
			gateway.recordLate(ctx, caller, exchange.records)
			writer.Header().Del("Content-Type")
			writeLLMError(writer, api, http.StatusBadGateway, "gateway_upstream", "The provider's answer was not a JSON object within the gateway's size limit.")
			return
		}
		exchange.response.Observe(raw)
		inspectLLMResponse(api, object, exchange.response)
		verdict := exchange.response.Verdict()
		exchange.record(DirectionResponse, verdict)
		if caller.Store.Record(ctx, "", exchange.records, nil) != nil {
			writer.Header().Del("Content-Type")
			writeLLMError(writer, api, http.StatusServiceUnavailable, "gateway_unavailable", "The gateway could not record its decision; nothing was returned.")
			return
		}
		if verdict.Decision == guardrail.DecisionBlock {
			writeLLMError(writer, api, http.StatusBadRequest, "guardrail_blocked", refusalText(verdict.Reason))
			return
		}
		if verdict.Decision == guardrail.DecisionRedact {
			raw = encodeJSON(object)
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(raw)
	}
}

// recordLate writes records whose answer does not wait for them.
func (gateway *Gateway) recordLate(ctx context.Context, caller Caller, records []Record) {
	if len(records) == 0 {
		return
	}
	late, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if caller.Store.Record(late, "", records, nil) != nil {
		gateway.RecordFailures.Add(1)
	}
}

type llmExchange struct {
	api      string
	provider string
	model    string
	agentID  string
	request  *Inspection
	response *Inspection
	records  []Record
}

func (exchange *llmExchange) record(direction string, verdict Verdict) {
	exchange.records = append(exchange.records, Record{Surface: SurfaceLLM, Operation: exchange.api, Direction: direction, Decision: verdict.Decision, Reason: verdict.Reason,
		Rules: verdict.Rules, Bytes: verdict.Bytes, Digest: verdict.Digest, Provider: exchange.provider, Model: exchange.model, AgentID: exchange.agentID})
}

// streamLLM relays a streamed answer through the window of TextStream.
func (gateway *Gateway) streamLLM(ctx context.Context, cancel context.CancelFunc, writer http.ResponseWriter, response *http.Response, caller Caller, exchange *llmExchange) {
	reader := newSSEReader(response.Body, gateway.maxResponse(), exchange.response.Observe)
	sseHeaders(writer.Header())
	writer.WriteHeader(http.StatusOK)
	out := newSSEWriter(writer)
	state := newLLMStream(exchange.api, exchange.response)
	deliver := func(events []sseEvent) bool {
		for _, event := range events {
			if out.Write(event) != nil {
				return false
			}
		}
		return true
	}
	for {
		event, err := reader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// The provider ended the stream: what is still held is
				// released, or the stream ends with the refusal.
				if rest, ok := state.flushAll(); ok {
					deliver(rest)
				} else {
					deliver([]sseEvent{state.refusal()})
				}
			} else if errors.Is(err, errEventTooLarge) {
				exchange.response.blocked, exchange.response.overflow = true, true
				deliver([]sseEvent{state.refusal()})
			}
			break
		}
		events, ok := state.event(event)
		if !ok {
			// Nothing more of the answer is forwarded; the provider is told
			// to stop.
			deliver([]sseEvent{state.refusal()})
			cancel()
			break
		}
		if !deliver(events) {
			break
		}
	}
	exchange.record(DirectionResponse, exchange.response.Verdict())
	gateway.recordLate(ctx, caller, exchange.records)
}
