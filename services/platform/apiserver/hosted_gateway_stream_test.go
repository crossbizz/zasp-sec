package apiserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/hostedgateway"
)

// A stream through the gateway lasts longer than the API server's read and
// write timeouts, which are sized for the product API's short requests. The
// server here has both at 300 ms; the provider's stream takes over a second.
func TestHostedGatewayStreamOutlivesTheServerTimeouts(t *testing.T) {
	provider := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		writer.Header().Set("Content-Type", "text/event-stream")
		for index := 0; index < 6; index++ {
			fmt.Fprintf(writer, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"piece %d. \"},\"finish_reason\":null}]}\n\n", index)
			writer.(http.Flusher).Flush()
			time.Sleep(200 * time.Millisecond)
		}
		fmt.Fprint(writer, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer provider.Close()
	f := newGatewayFixture(t, CredentialBearerToken, PermissionUseGateway)
	gateway, err := NewHostedGateway(HostedGatewayConfig{Timeout: 20 * time.Second,
		Providers: map[string]hostedgateway.Provider{"openai": {Name: "openai", BaseURL: provider.URL + "/v1", KeyHeader: "Authorization", Paths: map[string]string{hostedgateway.APIChatCompletions: "/chat/completions"}}},
		Upstream:  hostedgateway.UpstreamConfig{AllowAddress: func(address net.IP) bool { return address.IsLoopback() }, RootCAs: provider.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}})
	if err != nil {
		t.Fatal(err)
	}
	f.handler.gateway = gateway
	f.tx.payloads[currentGatewayOpenSQL] = `{"policy":{"version":0,"unapproved_servers":"allow","denied_tool_risks":[],"requests_per_minute":600},"guardrail":{"version":0,"rules":{}},"server":null,"rate_allowed":true}`
	f.tx.payloads[currentGatewayRecordSQL] = `{"recorded":2}`
	routed := RoutedOperation{OperationID: "createGatewayChatCompletion", PathParameters: map[string]string{}}
	checked := f.secondary.request(t, routed)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		for _, key := range []any{requestAuthorizationContextKey{}, requestAuthorizerContextKey{}} {
			ctx = context.WithValue(ctx, key, checked.Value(key))
		}
		f.handler.ServeHTTP(writer, request.WithContext(context.WithValue(ctx, identityContextKey{}, f.secondary.identity)), routed)
	}))
	server.Config.ReadTimeout, server.Config.WriteTimeout = 300*time.Millisecond, 300*time.Millisecond
	server.Start()
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/gateway/llm/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(hostedgateway.HeaderUpstreamAuthorization, "Bearer provider-key")
	started := time.Now()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !strings.HasSuffix(string(payload), "data: [DONE]\n\n") || !strings.Contains(string(payload), "piece 5. ") {
		t.Fatalf("the stream was cut after %v: err=%v status=%d body=%q", time.Since(started), err, response.StatusCode, payload)
	}
	if elapsed := time.Since(started); elapsed < time.Second {
		t.Fatalf("the stream ended after %v: it did not outlive the timeouts", elapsed)
	}
	// Both decisions were recorded once the stream had ended.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if statements, _ := f.tx.seen(); len(statements) == 2 && statements[1] == currentGatewayRecordSQL {
			break
		}
		if time.Now().After(deadline) {
			statements, _ := f.tx.seen()
			t.Fatalf("statements=%v", statements)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
