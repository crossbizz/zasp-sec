package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestStatelessToolsUseOnlyAuthorizedReads(t *testing.T) {
	visible := func(op string) bool { return op == "listAgents" || op == "getAttackPath" }
	calls := 0
	read := func(_ context.Context, op, id string, q url.Values) (int, []byte) {
		calls++
		if op != "listAgents" || id != "" || q.Get("limit") != "20" {
			t.Fatal("unexpected read", op, id, q)
		}
		return 200, []byte(`{"items":[],"next_cursor":null}`)
	}
	send := func(body string) string {
		t.Helper()
		r := httptest.NewRequest("POST", "https://zasp.example/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
		w := httptest.NewRecorder()
		Serve(w, r, visible, read)
		if w.Code != 200 || !json.Valid(w.Body.Bytes()) || w.Header().Get("Mcp-Session-Id") != "" {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		return w.Body.String()
	}
	out := send(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if !strings.Contains(out, "list_agents") || strings.Contains(out, "inspect_session") || strings.Contains(out, "propose_policy") {
		t.Fatal(out)
	}
	out = send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_agents","arguments":{}}}`)
	if !strings.Contains(out, "next_cursor") || calls != 1 {
		t.Fatal(out, calls)
	}
	for _, params := range []string{
		`{"name":"inspect_session","arguments":{}}`, `{"name":"get_attack_path","arguments":{"id":"../../private"}}`, `{"name":"request_containment","arguments":{}}`,
	} {
		out = send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":` + params + `}`)
		if calls != 1 {
			t.Fatal(out, calls)
		}
	}
}

func TestToolResultHidesDeniedRecord(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		value, _, err := result(code, []byte(`{"private":"restricted"}`))
		if value != nil || err == nil || strings.Contains(err.Error(), "restricted") {
			t.Fatal("leaked denied response")
		}
	}
}

func TestBatchCannotBypassPerRequestBound(t *testing.T) {
	r := httptest.NewRequest("POST", "https://zasp.example/mcp", strings.NewReader(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`))
	w := httptest.NewRecorder()
	Serve(w, r, nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("batch status %d", w.Code)
	}
}
