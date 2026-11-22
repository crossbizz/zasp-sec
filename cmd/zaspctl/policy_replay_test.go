package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGuardrailsSimulateUsesScopedPinnedReplay(t *testing.T) {
	const agent = "pid_00000001-0000-4000-8000-000000000001"
	const policy = "policy-workflow"
	from := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	bad := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/policies/"+policy+"/simulate" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer limited-synthetic" {
			t.Errorf("unexpected request: %s", r.URL.Path)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["schema_version"] != float64(2) || body["policy_revision"] != float64(3) || body["agent_id"] != agent || body["from"] != from.Format(time.RFC3339) {
			t.Errorf("unexpected selectors: %v", body)
		}
		revision := 3
		if bad {
			revision++
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"example_session_ids": []string{agent}, "matches": 1, "would_block": 1, "replay": map[string]any{"policy_revision": revision, "agent_id": agent, "from": from, "to": to, "evaluated": 250, "examined_count": 250, "eligible_count": 250, "would_block_rate": map[string]float64{"tool": 0.004}, "coverage": "indexed_events_only", "truncated": false, "next_window_to": nil, "next_before_event_id": nil}})
	}))
	defer srv.Close()
	t.Setenv("ZASP_API_URL", srv.URL)
	t.Setenv("ZASP_API_TOKEN", "limited-synthetic")
	args := []string{policy + "@3", "--agent", agent, "--since", from.Format(time.RFC3339)}
	var out, errs bytes.Buffer
	if code := runReplay(args, &out, &errs, srv.Client(), to); code != 0 || !strings.Contains(out.String(), `"examined_count": 250`) || strings.Contains(out.String(), "limited-synthetic") {
		t.Fatal(code, errs.String())
	}
	bad = true
	out.Reset()
	if code := runReplay(args, &out, &errs, srv.Client(), to); code == 0 || out.Len() != 0 {
		t.Fatal("foreign revision emitted")
	}
}
