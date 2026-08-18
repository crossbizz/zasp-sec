package reconciliation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestInventoryHTTPAuthorizedOperations(t *testing.T) {
	scope := fixtureScope(t, 1)
	store := NewMemoryStore()
	assets := []SourceAsset{
		{Scope: scope, Source: "aws", SourceID: "agent-1", Kind: KindAgent, Name: "Support agent", Owner: "security", Team: "agent-platform", Tags: []string{"production"}, EvidenceID: fixtureID(t, 31), SeenAt: fixtureTime()},
		{Scope: scope, Source: "github", SourceID: "tool-1", Kind: KindTool, Name: "Issue tool", EvidenceID: fixtureID(t, 32), SeenAt: fixtureTime()},
		{Scope: scope, Source: "idp", SourceID: "identity-1", Kind: KindIdentity, Name: "Service identity", CredentialReference: "connection_ref_identity", CredentialFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EvidenceID: fixtureID(t, 33), SeenAt: fixtureTime()},
		{Scope: scope, Source: "kubernetes", SourceID: "runtime-1", Kind: KindRuntime, Name: "support-agent-pod", WorkloadID: "pod/support-agent", SandboxID: "sandbox-1", Isolation: "container", EvidenceID: fixtureID(t, 34), SeenAt: fixtureTime()},
		{Scope: scope, Source: "aws", SourceID: "asset-1", Kind: KindAsset, Name: "Production queue", EvidenceID: fixtureID(t, 35), SeenAt: fixtureTime()},
	}
	reconciled := make([]Asset, len(assets))
	for index, asset := range assets {
		value, err := store.Reconcile(context.Background(), asset)
		if err != nil {
			t.Fatal(err)
		}
		reconciled[index] = value
	}
	projector := NewMemoryProjector()
	if err := ProjectRelationships(context.Background(), projector, scope, []Relationship{{From: reconciled[0].ID, To: reconciled[1].ID, Type: "uses", EvidenceID: fixtureID(t, 40)}}); err != nil {
		t.Fatal(err)
	}
	graph, err := NewCapabilityGraph([]CapabilityEdge{{Scope: scope, AgentID: reconciled[0].ID, TargetID: reconciled[1].ID, TargetKind: TargetTool, Category: CapabilityDataRead, Outcome: "read", EvidenceID: fixtureID(t, 41)}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewInventoryService(store, projector, graph, []AgentSession{{ID: fixtureID(t, 42), Scope: scope, AgentID: reconciled[0].ID, StartedAt: fixtureTime()}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewInventoryHTTPHandler(service, func(*http.Request) (domain.Scope, error) { return scope, nil }, func() time.Time { return fixtureTime().Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/api/v1/agents", "", http.StatusOK},
		{http.MethodGet, "/api/v1/agents/" + reconciled[0].ID.String(), "", http.StatusOK},
		{http.MethodPatch, "/api/v1/agents/" + reconciled[0].ID.String(), `{"owner":"platform","team":"security","tags":["critical"]}`, http.StatusOK},
		{http.MethodGet, "/api/v1/agents/" + reconciled[0].ID.String() + "/capabilities", "", http.StatusOK},
		{http.MethodGet, "/api/v1/agents/" + reconciled[0].ID.String() + "/relationships", "", http.StatusOK},
		{http.MethodGet, "/api/v1/agents/" + reconciled[0].ID.String() + "/sessions", "", http.StatusOK},
		{http.MethodGet, "/api/v1/tools", "", http.StatusOK},
		{http.MethodGet, "/api/v1/tools/" + reconciled[1].ID.String(), "", http.StatusOK},
		{http.MethodGet, "/api/v1/identities", "", http.StatusOK},
		{http.MethodGet, "/api/v1/identities/" + reconciled[2].ID.String(), "", http.StatusOK},
		{http.MethodGet, "/api/v1/runtimes", "", http.StatusOK},
		{http.MethodGet, "/api/v1/runtimes/" + reconciled[3].ID.String(), "", http.StatusOK},
		{http.MethodGet, "/api/v1/assets/" + reconciled[4].ID.String(), "", http.StatusOK},
	}
	for _, item := range cases {
		request := httptest.NewRequest(item.method, item.path, bytes.NewBufferString(item.body))
		if item.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != item.status {
			t.Fatalf("%s %s status=%d body=%s", item.method, item.path, response.Code, response.Body.String())
		}
		var payload any
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("%s %s invalid json: %v", item.method, item.path, err)
		}
	}
}

func TestInventoryHTTPRejectsBeforeParsingWithStableErrors(t *testing.T) {
	scope := fixtureScope(t, 1)
	store := NewMemoryStore()
	graph, _ := NewCapabilityGraph([]CapabilityEdge{{Scope: scope, AgentID: fixtureID(t, 20), TargetID: fixtureID(t, 21), TargetKind: TargetTool, Category: CapabilityDataRead, Outcome: "read", EvidenceID: fixtureID(t, 30)}})
	service, _ := NewInventoryService(store, NewMemoryProjector(), graph, nil)
	handler, err := NewInventoryHTTPHandler(service, func(*http.Request) (domain.Scope, error) { return domain.Scope{}, errors.New("denied") }, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/agents/"+fixtureID(t, 20).String(), bytes.NewBufferString(`{"owner":`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || response.Body.String() != "{\"code\":\"authorization_rejected\",\"correlation_id\":\"pid_ffffffff-ffff-4fff-8fff-ffffffffffff\",\"message\":\"Authorization rejected\",\"retryable\":false}\n" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}
