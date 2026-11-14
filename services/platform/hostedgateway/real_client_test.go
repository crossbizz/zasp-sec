package hostedgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRealMCPClientAndServerThroughTheGateway puts the gateway between a real
// MCP client and a real MCP server: the client and the server of the official
// MCP Python SDK, each in a process of its own, speaking Streamable HTTP. The
// client is run once with the initialize handshake ("legacy") and once in the
// mode in which it negotiates the newest revision it shares with the server
// ("auto"). The test is skipped where python3 with the mcp and uvicorn
// packages is not installed.
//
// The upstream here is plain HTTP on the loopback interface, which the
// deployed gateway refuses; the test's gateway is told to allow it.
func TestRealMCPClientAndServerThroughTheGateway(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	// -I keeps the interpreter from importing anything from the working
	// directory.
	if out, err := exec.Command(python, "-I", "-c", "import mcp, uvicorn, starlette").CombinedOutput(); err != nil {
		t.Skipf("the MCP Python SDK is not installed: %s", strings.TrimSpace(string(out)))
	}
	version, _ := exec.Command(python, "-I", "-c", "import importlib.metadata as m; print(m.version('mcp'))").Output()
	t.Logf("MCP Python SDK %s", strings.TrimSpace(string(version)))
	upstreamScript, _ := filepath.Abs(filepath.Join("testdata", "mcp_upstream.py"))
	clientScript, _ := filepath.Abs(filepath.Join("testdata", "mcp_client.py"))
	const upstreamCredentialValue = "Bearer upstream-credential-of-the-real-test"

	for _, test := range []struct{ mode, responses string }{{"legacy", "sse"}, {"legacy", "json"}, {"auto", "sse"}} {
		t.Run(test.mode+" client, "+test.responses+" answers", func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			arguments := []string{"-I", upstreamScript, fmt.Sprint(port), upstreamCredentialValue}
			if test.responses == "json" {
				arguments = append(arguments, "json")
			}
			upstream := exec.CommandContext(ctx, python, arguments...)
			upstream.Dir = t.TempDir()
			var upstreamLog strings.Builder
			upstream.Stdout, upstream.Stderr = &upstreamLog, &upstreamLog
			if err := upstream.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = upstream.Process.Kill(); _ = upstream.Wait() }()
			address := fmt.Sprintf("http://127.0.0.1:%d/mcp", port)
			for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
				if connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
					connection.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the upstream MCP server did not start: %s", upstreamLog.String())
				}
			}

			session := Session{Policy: Policy{Version: 1, UnapprovedServers: "allow", DeniedToolRisks: []string{"execute"}}, Server: &Server{ID: "server-1", Name: "tickets", UpstreamURL: address, Enabled: true, Approval: "approved"}}
			store := &memoryStore{session: session}
			gateway := &Gateway{Client: NewUpstreamClient(UpstreamConfig{AllowAddress: func(ip net.IP) bool { return ip.IsLoopback() }}), Limiter: NewRateLimiter(nil), Timeout: 30 * time.Second,
				AllowUpstreamURL: func(value string) bool { return value == address }}
			var methods []string
			front := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				// What the API's middleware and router do before the gateway.
				if request.Header.Get("Authorization") != "Bearer "+platformToken {
					writer.WriteHeader(http.StatusUnauthorized)
					return
				}
				caller := Caller{Store: store, TokenKey: "token-1"}
				switch request.Method {
				case http.MethodPost:
					body, _ := io.ReadAll(request.Body)
					var message struct {
						Method string `json:"method"`
					}
					_ = json.Unmarshal(body, &message)
					store.mu.Lock()
					methods = append(methods, message.Method)
					store.mu.Unlock()
					gateway.ServeMCP(writer, request, caller, "server-1", body)
				case http.MethodDelete:
					gateway.CloseMCP(writer, request, caller, "server-1")
				default:
					writer.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer front.Close()

			client := exec.CommandContext(ctx, python, "-I", clientScript, front.URL+"/mcp/server-1", platformToken, upstreamCredentialValue, test.mode)
			client.Dir = t.TempDir()
			var clientErrors strings.Builder
			client.Stderr = &clientErrors
			out, err := client.Output()
			if err != nil {
				t.Fatalf("the MCP client failed: %v\nclient: %s\nupstream: %s", err, clientErrors.String(), upstreamLog.String())
			}
			var seen struct {
				Tools []string `json:"tools"`
				Calls map[string]struct {
					IsError bool   `json:"is_error"`
					Raised  string `json:"raised"`
					Text    string `json:"text"`
				} `json:"calls"`
			}
			if err := json.Unmarshal(out, &seen); err != nil {
				t.Fatalf("client output %q: %v", out, err)
			}
			// The tool that runs commands is hidden by the policy.
			if strings.Join(seen.Tools, ",") != "lookup_customer,read_page" {
				t.Fatalf("tools the client saw: %v", seen.Tools)
			}
			// The argument was redacted before the upstream saw it (the
			// upstream echoes it), and the result before the client did.
			if call := seen.Calls["lookup_customer"]; call.IsError || call.Raised != "" || call.Text != "Customer Jane, [REDACTED:pii.email], asked about: the account of [REDACTED:pii.email]" {
				t.Fatalf("lookup_customer: %+v", call)
			}
			// A result that carries an instruction reaches the client as a
			// failed tool call, as does a call of a denied tool.
			for _, name := range []string{"read_page", "run_shell"} {
				call := seen.Calls[name]
				if !(call.IsError || call.Raised != "") || !strings.Contains(call.Text, "Blocked by the gateway") || strings.Contains(call.Text, "attacker") || strings.Contains(call.Text, "ran id") {
					t.Fatalf("%s: %+v", name, call)
				}
			}
			records, tools := store.taken()
			var decisions []string
			for _, record := range records {
				decisions = append(decisions, record.Operation+" "+record.Direction+" "+record.ToolName+" "+record.Decision+" "+record.Reason)
				if record.AgentID != "real-mcp-client" {
					t.Fatalf("record without the agent: %+v", record)
				}
			}
			want := []string{
				"tools/list response  redact tools_hidden",
				"tools/call request lookup_customer redact guardrail", "tools/call response lookup_customer redact guardrail",
				"tools/call request read_page allow none", "tools/call response read_page block guardrail",
				"tools/call request run_shell block tool_risk_denied",
			}
			if strings.Join(decisions, "; ") != strings.Join(want, "; ") {
				t.Fatalf("decisions:\n got %s\nwant %s", strings.Join(decisions, "; "), strings.Join(want, "; "))
			}
			if len(tools) != 3 {
				t.Fatalf("tools noted for the inventory: %+v", tools)
			}
			store.mu.Lock()
			t.Logf("methods the client sent through the gateway: %s", strings.Join(methods, ", "))
			store.mu.Unlock()
		})
	}
}
