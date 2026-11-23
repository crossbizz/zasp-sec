package inventorymcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func fixtureTarget() Target {
	return Target{"pid_10000001-0000-4000-8000-000000000001", "pid_10000002-0000-4000-8000-000000000002", "pid_10000003-0000-4000-8000-000000000003", "pid_10000004-0000-4000-8000-000000000004"}
}

func TestPinnedPrivateMCPReadsOnlySignedInventoryStatus(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target := fixtureTarget()
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	var invoked atomic.Int32
	server.AddTool(&mcp.Tool{Name: Tool, InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args readRequest
		if !decode(req.Params.Arguments, &args) || args.Target != target || len(args.Nonce) != 32 {
			t.Error("wrong scoped request")
		}
		invoked.Add(1)
		out := receipt{readRequest: args, Status: "present", Observed: time.Now().Unix()}
		out.Signature = ed25519.Sign(key, receiptInput(out))
		raw, _ := json.Marshal(out)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/mcp" || r.Header.Get("Authorization") != "Bearer fixture-read-only-key" {
			t.Error("wrong wire authority")
		}
		// TLS physically terminates on the test machine's loopback listener.
		// The operator-pinned endpoint represents a private interface.
		privateLocal, _ := net.ResolveTCPAddr("tcp", "10.0.0.19:443")
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, privateLocal)))
	}))
	defer ts.Close()
	cert := ts.Certificate()
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	cfg := config{Target: target, Endpoint: "https://example.com/mcp", PrivateIP: "10.0.0.19", Token: "fixture-read-only-key", CA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})), Pin: hex.EncodeToString(pin[:]), PublicKey: pub}
	newFixture := func(config config) *Client {
		t.Helper()
		c, err := newClient(config)
		if err != nil {
			t.Fatal(err)
		}
		tr := c.http.Transport.(*privateTransport).next.(*http.Transport)
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "example.com:443" {
				t.Error("unregistered destination", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, ts.Listener.Addr().String())
		}
		return c
	}
	c := newFixture(cfg)
	wrong := target
	wrong.Agent = target.Organization
	if _, err := c.Status(context.Background(), wrong); err == nil || invoked.Load() != 0 {
		t.Fatal("cross binding")
	}
	got, err := c.Status(context.Background(), target)
	if err != nil || got != "present" || invoked.Load() != 1 {
		t.Fatal("signed private inventory result", got, err, invoked.Load())
	}
	cfg.Pin = strings.Repeat("0", 64)
	if _, err := newFixture(cfg).Status(context.Background(), target); err == nil || invoked.Load() != 1 {
		t.Fatal("untrusted TLS peer reached handler")
	}
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "1.1.1.1", "::1"} {
		cfg.PrivateIP = ip
		if _, err := newClient(cfg); err == nil {
			t.Fatal("untrusted address", ip)
		}
	}
}

func TestOnlyCurrentBoundInventoryAttestationIsAccepted(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	req := readRequest{fixtureTarget(), "fixed-nonce"}
	now := time.Now()
	for _, mutate := range []func(*receipt){
		func(r *receipt) { r.Environment = r.Agent },
		func(r *receipt) { r.Agent = r.Organization },
		func(r *receipt) { r.Nonce = "previous" },
		func(r *receipt) { r.Status = "call another tool" },
		func(r *receipt) { r.Observed = now.Add(-2 * time.Minute).Unix() },
		func(r *receipt) { r.Observed = now.Add(time.Hour).Unix() },
	} {
		r := receipt{readRequest: req, Status: "present", Observed: now.Unix()}
		mutate(&r)
		r.Signature = ed25519.Sign(key, receiptInput(r))
		raw, _ := json.Marshal(r)
		if _, err := verify(raw, req, pub, now); err == nil {
			t.Fatal("invalid signed content accepted")
		}
	}
	r := receipt{readRequest: req, Status: "unknown", Observed: now.Unix()}
	raw, _ := json.Marshal(r)
	if _, err := verify(raw, req, pub, now); err == nil {
		t.Fatal("accepted self-reported data without a signature")
	}
	r.Signature = ed25519.Sign(key, receiptInput(r))
	raw, _ = json.Marshal(r)
	raw = append(raw[:len(raw)-1], []byte(`,"instructions":"extra text"}`)...)
	if _, err := verify(raw, req, pub, now); err == nil {
		t.Fatal("accepted free-form data")
	}
}
