package hostedgateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/hostedgateway/gatewaytest"
)

// TestRealModelSDKsThroughTheProxy points the providers' own Python SDKs
// (openai and anthropic) at the model proxy, configured the way the hosted
// gateway guide says: the base URL is the gateway's, the platform token is
// what the SDK authenticates with, and the provider's key travels beside it.
// The provider is a local stand-in over HTTPS, so this proves the SDKs
// accept the proxy's answers, streams and errors; it does not prove anything
// about a real provider.
//
// It needs a Python with both packages: ZASP_GATEWAY_SDK_PYTHON names it,
// otherwise python3 is tried. Without them the test is skipped.
func TestRealModelSDKsThroughTheProxy(t *testing.T) {
	python := os.Getenv("ZASP_GATEWAY_SDK_PYTHON")
	if python == "" {
		python = "python3"
	}
	if out, err := exec.Command(python, "-I", "-c", "import openai, anthropic").CombinedOutput(); err != nil {
		t.Skipf("no Python with the openai and anthropic packages (set ZASP_GATEWAY_SDK_PYTHON): %s", strings.TrimSpace(string(out)))
	}
	script, _ := filepath.Abs(filepath.Join("testdata", "llm_sdk_client.py"))
	provider := gatewaytest.NewProvider(providerKey)
	defer provider.Server.Close()

	store := &memoryStore{session: Session{Policy: Policy{Version: 1, UnapprovedServers: "allow"}}}
	gateway := &Gateway{
		Client:  NewUpstreamClient(UpstreamConfig{AllowAddress: func(address net.IP) bool { return address.IsLoopback() }, RootCAs: provider.Server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}),
		Limiter: NewRateLimiter(nil), Timeout: 30 * time.Second,
		Providers: map[string]Provider{
			"openai":    {Name: "openai", BaseURL: provider.Server.URL + "/v1", KeyHeader: "Authorization", Paths: map[string]string{APIChatCompletions: "/chat/completions", APIResponses: "/responses"}},
			"anthropic": {Name: "anthropic", BaseURL: provider.Server.URL + "/v1", KeyHeader: "x-api-key", Paths: map[string]string{APIMessages: "/messages"}, Forward: []string{"anthropic-version", "anthropic-beta"}},
		},
	}
	front := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// What the API's middleware and router do before the proxy.
		if request.Header.Get("Authorization") != "Bearer "+platformToken || request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(request.Body)
		caller := Caller{Store: store, TokenKey: "token-1"}
		switch request.URL.Path {
		case "/api/v1/gateway/llm/v1/chat/completions":
			gateway.ServeLLM(writer, request, caller, APIChatCompletions, body)
		case "/api/v1/gateway/llm/v1/responses":
			gateway.ServeLLM(writer, request, caller, APIResponses, body)
		case "/api/v1/gateway/llm/v1/messages":
			gateway.ServeLLM(writer, request, caller, APIMessages, body)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer front.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := exec.CommandContext(ctx, python, "-I", script, front.URL, platformToken, providerKey)
	client.Dir, client.Env = t.TempDir(), localProcessEnvironment()
	var clientErrors strings.Builder
	client.Stderr = &clientErrors
	out, err := client.Output()
	if err != nil {
		t.Fatalf("the SDK client failed: %v\n%s", err, clientErrors.String())
	}
	versions, problems := provider.CheckSDKRun(out, platformToken)
	t.Log(versions)
	for _, problem := range problems {
		t.Error(problem)
	}
}
