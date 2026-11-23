package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/inventorymcp"
)

// The connector has its own signed TLS/MCP transport tests. This fixture
// exercises the complete product permission, step lease and read/answer path.
func exerciseStudioInventoryTurn(t *testing.T, b *installedBaseline, h *discoveryWorkflowSurface, admin installedPrincipal, session, event, agent string) {
	t.Helper()
	target := inventorymcp.Target{Organization: b.o, Workspace: b.w, Environment: b.e, Agent: agent}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	peer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := peer.Certificate()
	peer.Close()
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	data, _ := json.Marshal(map[string]any{"organization_id": b.o, "workspace_id": b.w, "environment_id": b.e, "agent_id": agent, "endpoint": "https://private.example/mcp", "private_ip": "10.0.0.24", "ca_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})), "tls_spki_sha256": hex.EncodeToString(pin[:]), "receipt_public_key": pub, "read_token": "fixture-private-only"})
	f := filepath.Join(t.TempDir(), "binding.json")
	if err := os.WriteFile(f, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZASP_STUDIO_INVENTORY_MCP_FILE", f)
	b.seed(func() {
		seedCurrentMCPAgent(b, admin, agent)
	})
	calls := 0
	h.analyst.inventoryStatus = func(_ context.Context, wanted inventorymcp.Target) (string, error) {
		calls++
		if wanted != target {
			t.Fatal("wrong authorized external lookup", wanted)
		}
		return "present", nil
	}
	studio := studioDefinition{Name: "Inventory review", Mission: "Check the assigned inventory record", Trigger: "manual", Tools: []string{"inspect_session", inventorymcp.Tool}, ApprovalTools: []string{"inspect_session", inventorymcp.Tool}, Proposal: "none", Approval: true, Steps: 2, Budget: 100, Model: h.analyst.binding.Model}
	raw, _ := json.Marshal(studio)
	saved := b.serve(h, admin, "createCustomSecurityAgent", "POST", "/api/v1/security-agents/custom", nil, string(raw), map[string]string{"Idempotency-Key": b.id()})
	var def struct {
		ID string `json:"id"`
	}
	if saved.Code != 200 || json.Unmarshal(saved.Body.Bytes(), &def) != nil || !validProductID(def.ID) {
		t.Fatalf("external profile %d %s", saved.Code, saved.Body)
	}
	base := "/api/v1/security-agents/chat/threads"
	q := "?session_id=" + session
	created := b.serve(h, admin, "createAnalystThread", "POST", base+q, nil, `{"session_id":"`+session+`","studio_id":"`+def.ID+`","studio_revision":1}`, map[string]string{"Idempotency-Key": b.id()})
	var thread analystThread
	if created.Code != 200 || json.Unmarshal(created.Body.Bytes(), &thread) != nil || !validProductID(thread.ID) {
		t.Fatalf("external thread %d %s", created.Code, created.Body)
	}
	params := map[string]string{"id": thread.ID}
	got := b.serve(h, admin, "getAnalystThread", "GET", base+"/"+thread.ID+q, params, "", nil)
	if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &thread) != nil || !thread.RequiresExternalApproval || !thread.RequiresReadApproval {
		t.Fatalf("approval disclosure %d %s", got.Code, got.Body)
	}
	repo, err := NewPostgresInventoryRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	reads, err := newInventoryHTTPHandler(repo, bytes.Repeat([]byte{0x08}, 32))
	if err != nil {
		t.Fatal(err)
	}
	composed, err := NewComposition(Dependencies{Authorizer: b.authorizer, Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: reads, Risk: handlerResponse("risk"), Workflow: h, Connector: handlerResponse("connector")})
	if err != nil {
		t.Fatal(err)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(expectedScopeHeader, expectedScopeValue(admin.identity.Scope))
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), productRouterContextKey{}, composed)))
	})
	run := func(key string, tools []string) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"message": "Review this session", "request_id": key, "approved_read_tools": tools})
		return b.serve(wrapped, admin, "streamAnalystThread", "POST", base+"/"+thread.ID+"/stream"+q, params, string(raw), nil)
	}
	for _, tools := range [][]string{nil, {"inspect_session"}, {inventorymcp.Tool}} {
		if v := run(b.id(), tools); v.Code != 409 || !strings.Contains(v.Body.String(), "tool_approval_required") || calls != 0 {
			t.Fatalf("consent %d %s", v.Code, v.Body)
		}
	}
	required := []string{"inspect_session", inventorymcp.Tool}
	if v := run(b.id(), required); v.Code != 409 || !strings.Contains(v.Body.String(), "session_evidence_missing") || calls != 0 {
		t.Fatalf("weak attribution %d %s", v.Code, v.Body)
	}
	b.seed(func() {
		b.exec(`UPDATE zasp_runtime_session_events SET confidence='exact' WHERE (organization_id,workspace_id,environment_id,event_id)=($1,$2,$3,$4)`, b.o, b.w, b.e, event)
	})
	key := b.id()
	for range 2 {
		v := run(key, required)
		if v.Code != 200 || !strings.Contains(v.Body.String(), "[DONE]") || !strings.Contains(v.Body.String(), "The private inventory lists this agent.") || calls != 1 {
			t.Fatalf("scoped external read %d calls %d %s", v.Code, calls, v.Body)
		}
	}
	if v := run(b.id(), required); v.Code != 409 || !strings.Contains(v.Body.String(), "investigation_limit") || calls != 1 {
		t.Fatalf("external step budget %d calls %d %s", v.Code, calls, v.Body)
	}
}
