package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func watchID(n int) string { return fmt.Sprintf("pid_a5000001-0000-4000-8000-%012d", n) }
func watchConsentFixture(now time.Time) ticketConsent {
	return ticketConsent{Version: "ticket-watch.v1", Environment: "test", Enabled: true, Binding: Binding{watchID(1), watchID(2), watchID(3), watchID(4), 1}, Definition: watchID(5), Target: watchID(6), Server: watchID(7), DefinitionVersion: 1, ScheduleVersion: 2, Cohort: "ticket", View: "pilot", Expires: now.Add(24 * time.Hour)}
}
func watchHash(s string) string { return "sha256:" + strings.Repeat(s, 64) }
func schemaFixture(c ticketConsent, selected, other, metadata string) []byte {
	b, _ := json.Marshal(map[string]any{"schema_version": "zasp.mcp-tool-contract.v1", "source": "operator_supplied_tools_list", "scope": map[string]string{"environment_id": c.Binding.Environment, "server_id": c.Server, "view": c.View}, "tools": []map[string]string{{"name": "unrelated", "input_digest": other, "metadata_digest": metadata}, {"name": "update_ticket", "input_digest": selected, "metadata_digest": metadata}}})
	return b
}
func TestTicketWatchRelevantAndScopedRevisions(t *testing.T) {
	now := time.Now().UTC()
	c := watchConsentFixture(now)
	r := watchRevision{Policy: 1, Artifact: watchHash("a"), Input: watchHash("b")}
	dir := filepath.Join(t.TempDir(), "watch")
	run := watchApproval{}
	calls := 0
	w := ticketWatcher{dir: dir, consent: c, now: func() time.Time { return now }, approved: func(context.Context, ticketConsent) (watchApproval, error) { return run, nil }, execute: func(context.Context, string, string, uint64) string { calls++; return "passed" }}
	step := func(want string) {
		t.Helper()
		got, err := w.cycle(context.Background(), r)
		if err != nil || got.Status != want {
			t.Fatalf("step want %s got %+v %v", want, got, err)
		}
	}
	step("baseline")
	step("already_observed")
	raw := schemaFixture(c, r.Input, watchHash("c"), watchHash("d"))
	in, out, err := ticketSchema(raw, c)
	if err != nil || in != r.Input || out != "" {
		t.Fatal("scoped schema could not be used")
	}
	if changed, _, err := ticketSchema(schemaFixture(c, r.Input, watchHash("f"), watchHash("e")), c); err != nil || changed != in {
		t.Fatal("unrelated tool or metadata triggered a revision")
	}
	for _, changed := range []string{"scope", "server", "view", "unknown", "duplicate"} {
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		sc := doc["scope"].(map[string]any)
		arr := doc["tools"].([]any)
		switch changed {
		case "scope":
			sc["environment_id"] = watchID(10)
		case "server":
			sc["server_id"] = watchID(11)
		case "view":
			sc["view"] = "other"
		case "unknown":
			doc["tools"] = arr[:1]
		case "duplicate":
			doc["tools"] = append(arr, arr[1])
		}
		value, _ := json.Marshal(doc)
		if _, _, err := ticketSchema(value, c); err == nil {
			t.Fatalf("accepted %s", changed)
		}
	}
	for i, field := range []string{"policy", "artifact", "schema"} {
		now = now.Add(2 * time.Hour)
		switch field {
		case "policy":
			r.Policy++
		case "artifact":
			r.Artifact = watchHash("f")
		case "schema":
			r.Input = watchHash("e")
		}
		run = watchApproval{watchID(60 + i), now.Add(-time.Minute)}
		step("pending_approved_schedule")
		run.Queued = now
		step("passed")
		step("already_observed")
	}
	if calls != 3 {
		t.Fatalf("dispatched %d", calls)
	}
	r.Policy++
	step("cooldown")
	now = now.Add(2 * time.Hour)
	run.Queued = now
	step("pending_unused_run")
	run.Run = watchID(71)
	step("passed")
	// The file reservation survives a process stop. Resuming cannot duplicate the side effect.
	raw, err = os.ReadFile(filepath.Join(dir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var j watchJournal
	if json.Unmarshal(raw, &j) != nil {
		t.Fatal("invalid journal")
	}
	k := watchKey(r)
	row := j.Seen[k]
	row.Status = "reserved"
	j.Seen[k] = row
	if saveWatchJournal(filepath.Join(dir, "journal.json"), j) != nil {
		t.Fatal("journal save failed")
	}
	step("inconclusive_interrupted")
	wrong := c
	wrong.Binding.Environment = watchID(12)
	if wrong.valid(c.Binding, now) {
		t.Fatal("cross-scope consent accepted")
	}
	w.consent = wrong
	if _, err = w.cycle(context.Background(), r); err == nil {
		t.Fatal("foreign journal reused")
	}
	w.consent = c
	w.consent.Enabled = false
	step("disabled")
}
func TestTicketWatchProductReadBoundaries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := watchConsentFixture(now)
	run := watchID(9)
	goodDef := map[string]any{"id": c.Definition, "version": c.DefinitionVersion, "target_id": c.Target, "target_kind": "mcp_server", "enabled": true, "safety": map[string]any{"environment": "test", "credential_class": "test_write", "expected_side_effects": []string{"synthetic_ticket_update"}}}
	goodSchedule := map[string]any{"definition_id": c.Definition, "version": c.ScheduleVersion, "enabled": true, "last_run_id": run, "last_outcome": "queued", "last_fired_at": now}
	goodRun := map[string]any{"id": run, "definition_id": c.Definition, "definition_version": c.DefinitionVersion, "status": "queued", "queued_at": now}
	for _, mode := range []string{"valid", "scope", "unauthorized", "disabled", "definition_changed", "foreign_target", "extra_effect", "production", "older_schedule", "cancelled", "not_scheduled"} {
		t.Run(mode, func(t *testing.T) {
			var paths []string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer operator-read-only" {
					t.Error("unexpected request")
				}
				expected := strings.Join([]string{c.Binding.Organization, c.Binding.Workspace, c.Binding.Environment}, "/")
				if r.Header.Get("X-Zasp-Expected-Scope") != expected {
					t.Error("unbound request")
				}
				if mode == "unauthorized" {
					w.WriteHeader(403)
					return
				}
				if mode == "scope" {
					expected = "wrong"
				}
				w.Header().Set("X-Zasp-Verified-Scope", expected)
				paths = append(paths, r.URL.Path)
				var d map[string]any
				switch r.URL.Path {
				case "/api/v1/tests/" + c.Definition:
					d = goodDef
				case "/api/v1/tests/" + c.Definition + "/schedule":
					d = goodSchedule
				case "/api/v1/test-runs/" + run:
					d = goodRun
				default:
					t.Error("unrecognized product read")
					w.WriteHeader(404)
					return
				}
				raw, _ := json.Marshal(d)
				var v map[string]any
				_ = json.Unmarshal(raw, &v)
				switch mode {
				case "disabled":
					v["enabled"] = false
				case "definition_changed":
					v["version"] = 43
				case "foreign_target":
					v["target_id"] = watchID(12)
				case "older_schedule":
					if v["last_run_id"] != nil {
						v["version"] = 1
					}
				case "extra_effect", "production":
					if safety, ok := v["safety"].(map[string]any); ok {
						if mode == "production" {
							safety["environment"] = "production"
						} else {
							safety["expected_side_effects"] = []string{"synthetic_ticket_update", "extra"}
						}
					}
				case "cancelled":
					v["cancel_requested"] = true
				case "not_scheduled":
					v["last_fired_at"] = now.Add(-time.Hour)
				}
				_ = json.NewEncoder(w).Encode(v)
			}))
			defer srv.Close()
			reader := ticketProductReader{srv.Client(), srv.URL, "operator-read-only", c.Binding}
			p, err := reader.approval(context.Background(), c)
			if mode == "valid" {
				if err != nil || p.Run != run || len(paths) != 3 {
					t.Fatalf("valid approval failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("ineligible was accepted")
			}
		})
	}
}
