package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

const exportPlannerSelection = `[{"source_kind":"finding","source_id":"pid_71000001-0000-4000-8000-000000000001","source_version":9,"association_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"source_kind":"run_audit","source_id":"pid_71000002-0000-4000-8000-000000000002","source_version":1,"association_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]`

func exportPlannerContext(t *testing.T, selection string) securityAgentPlannerContext {
	t.Helper()
	c := testSecurityAgentPlannerContext()
	c.AllowedActions = []string{"create_evidence_export"}
	c.AllowedTargets = []string{c.RunID}
	// Inject wire data so the first regression can run before the context field
	// exists. This is fixture construction, not the validator under test.
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"ExportSelection":`+selection+`}`)...)
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func exportPlanner(t *testing.T, candidate string) (*productionSecurityAgentPlanner, *securityAgentPlannerTransport) {
	t.Helper()
	transport := &securityAgentPlannerTransport{responseStatus: http.StatusOK, responseBody: openRouterPlannerResponse(candidate)}
	p, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 4096, PolicyVersion: "security-agent-planner-v1", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, transport
}

func exportPlannerCandidate(selection string) string {
	return `{"version":1,"summary":"Export retained run evidence","steps":[{"index":0,"action":"create_evidence_export","target_id":"pid_70000004-0000-4000-8000-000000000004","evidence_ids":` + selection + `}]}`
}

func TestSecurityAgentExportPlannerRetainsExactSubsetAndOrder(t *testing.T) {
	var refs []json.RawMessage
	if err := json.Unmarshal([]byte(exportPlannerSelection), &refs); err != nil {
		t.Fatal(err)
	}
	for _, selection := range []string{exportPlannerSelection, "[" + string(refs[1]) + "," + string(refs[0]) + "]", "[" + string(refs[1]) + "]"} {
		p, transport := exportPlanner(t, exportPlannerCandidate(selection))
		result := p.Plan(context.Background(), exportPlannerContext(t, exportPlannerSelection))
		if result.Failure != "" || len(result.Candidate.Steps) != 1 {
			t.Fatalf("valid selection refused: %+v", result)
		}
		encoded, err := json.Marshal(result.Candidate.Steps[0])
		if err != nil {
			t.Fatal(err)
		}
		var step map[string]json.RawMessage
		if json.Unmarshal(encoded, &step) != nil || string(step["evidence_ids"]) != selection {
			t.Fatalf("selection changed: %s", encoded)
		}
		var request struct {
			Messages       []struct{ Content string } `json:"messages"`
			ResponseFormat struct {
				JSONSchema struct {
					Schema map[string]any `json:"schema"`
				} `json:"json_schema"`
			} `json:"response_format"`
		}
		if json.Unmarshal(transport.requestBody, &request) != nil || len(request.Messages) != 2 || !strings.Contains(request.Messages[1].Content, `"export_selection":`+exportPlannerSelection) {
			t.Fatal("trusted selection missing from model request")
		}
		stepSchema := request.ResponseFormat.JSONSchema.Schema["properties"].(map[string]any)["steps"].(map[string]any)["items"].(map[string]any)
		if !slices.Contains(stepSchema["required"].([]any), any("evidence_ids")) || stepSchema["additionalProperties"] != false {
			t.Fatal("provider response contract does not require closed export arguments")
		}
		properties := stepSchema["properties"].(map[string]any)
		if properties["action"].(map[string]any)["const"] != "create_evidence_export" || properties["target_id"].(map[string]any)["const"] != "pid_70000004-0000-4000-8000-000000000004" || properties["evidence_ids"].(map[string]any)["items"].(map[string]any)["additionalProperties"] != false {
			t.Fatal("provider response contract widened export authority")
		}
	}
}

func TestSecurityAgentExportPlannerRejectsInventedOrMalformedSelection(t *testing.T) {
	var refs []json.RawMessage
	if err := json.Unmarshal([]byte(exportPlannerSelection), &refs); err != nil {
		t.Fatal(err)
	}
	for name, selection := range map[string]string{
		"empty": "[]", "null": "null",
		"foreign id":          strings.Replace(exportPlannerSelection, "71000001", "71000009", 1),
		"new version":         strings.Replace(exportPlannerSelection, `"source_version":9`, `"source_version":10`, 1),
		"changed association": strings.Replace(exportPlannerSelection, "sha256:aaaa", "sha256:cccc", 1),
		"changed kind":        strings.Replace(exportPlannerSelection, `"finding"`, `"attack_path"`, 1),
		"duplicate ref":       "[" + string(refs[0]) + "," + string(refs[0]) + "]",
		"private field":       strings.Replace(exportPlannerSelection, `"source_version":9`, `"source_version":9,"storage_key":"private"`, 1),
		"duplicate key":       strings.Replace(exportPlannerSelection, `"source_version":9`, `"source_version":8,"source_version":9`, 1),
		"case alias":          strings.Replace(exportPlannerSelection, `"source_kind"`, `"Source_Kind"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := exportPlanner(t, exportPlannerCandidate(selection))
			result := p.Plan(context.Background(), exportPlannerContext(t, exportPlannerSelection))
			if result.Failure != securityAgentPlannerRejected || len(result.Candidate.Steps) != 0 {
				t.Fatalf("untrusted selection admitted: %+v", result)
			}
		})
	}
}

func TestSecurityAgentExportPlannerFreezesSelection(t *testing.T) {
	c := exportPlannerContext(t, exportPlannerSelection)
	p, _ := exportPlanner(t, exportPlannerCandidate(exportPlannerSelection))
	prepared, err := p.Prepare(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.ExportSelection[0].Version = 99
	result := prepared.Dispatch(context.Background())
	if result.Failure != "" || result.Candidate.Steps[0].EvidenceIDs[0].Version != 9 {
		t.Fatalf("caller mutated prepared authority: %+v", result)
	}
}

func TestSecurityAgentExportPlannerRefusesCrossActionOrParentAuthority(t *testing.T) {
	for _, mode := range []string{"foreign parent context", "nonexport context", "foreign parent candidate", "missing selection", "nonexport selection"} {
		t.Run(mode, func(t *testing.T) {
			c := exportPlannerContext(t, exportPlannerSelection)
			body := exportPlannerCandidate(exportPlannerSelection)
			want := securityAgentPlannerRejected
			calls := 1
			switch mode {
			case "foreign parent context":
				c.AllowedTargets = []string{c.EnvironmentID}
				want = securityAgentPlannerUnavailable
				calls = 0
			case "nonexport context":
				c.AllowedActions = []string{"update_finding_response"}
				want = securityAgentPlannerUnavailable
				calls = 0
			case "foreign parent candidate":
				body = strings.Replace(body, c.RunID, c.EnvironmentID, 1)
			case "missing selection":
				body = strings.Replace(body, `,"evidence_ids":`+exportPlannerSelection, "", 1)
			case "nonexport selection":
				c = testSecurityAgentPlannerContext()
				body = strings.Replace(body, "create_evidence_export", "update_finding_response", 1)
				body = strings.Replace(body, "pid_70000004-0000-4000-8000-000000000004", c.AllowedTargets[0], 1)
			}
			p, transport := exportPlanner(t, body)
			result := p.Plan(context.Background(), c)
			if result.Failure != want || transport.calls != calls || len(result.Candidate.Steps) != 0 {
				t.Fatalf("authority widened: %+v calls%d", result, transport.calls)
			}
		})
	}
}

func TestSecurityAgentExportPlannerSupportsAllReferenceKindsAndBounds(t *testing.T) {
	for _, kind := range []string{"finding", "attack_path", "runtime_decision", "run_audit", "manual", "existing_test", "attack_lab"} {
		id := "pid_71000001-0000-4000-8000-000000000001"
		if kind == "manual" {
			id = strings.Repeat("c", 64)
		}
		selection := fmt.Sprintf(`[{"source_kind":%q,"source_id":%q,"source_version":9007199254740991,"association_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]`, kind, id)
		p, _ := exportPlanner(t, exportPlannerCandidate(selection))
		result := p.Plan(context.Background(), exportPlannerContext(t, selection))
		if result.Failure != "" {
			t.Fatalf("kind %s rejected: %+v", kind, result)
		}
	}
	for _, count := range []int{100, 101} {
		refs := make([]string, count)
		for i := range refs {
			refs[i] = fmt.Sprintf(`{"source_kind":"run_audit","source_id":"pid_71000001-0000-4000-8000-%012d","source_version":1,"association_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, i+1)
		}
		selection := "[" + strings.Join(refs, ",") + "]"
		c := exportPlannerContext(t, selection)
		p, transport := exportPlanner(t, exportPlannerCandidate(selection))
		result := p.Plan(context.Background(), c)
		if count == 100 && (result.Failure != "" || len(result.Candidate.Steps) != 1 || len(result.Candidate.Steps[0].EvidenceIDs) != 100 || transport.calls != 1) || count == 101 && (result.Failure != securityAgentPlannerUnavailable || transport.calls != 0) {
			t.Fatalf("count%d result=%+v calls%d", count, result, transport.calls)
		}
	}
}

func TestSecurityAgentExportPlannerRequiresTrustedSelectionBeforeProviderCall(t *testing.T) {
	for name, selection := range map[string]string{"missing": "null", "empty": "[]", "invalid version": strings.Replace(exportPlannerSelection, `"source_version":9`, `"source_version":0`, 1), "invalid digest": strings.Replace(exportPlannerSelection, "sha256:aaaa", "sha256:zzzz", 1)} {
		t.Run(name, func(t *testing.T) {
			p, transport := exportPlanner(t, exportPlannerCandidate(exportPlannerSelection))
			result := p.Plan(context.Background(), exportPlannerContext(t, selection))
			if result.Failure != securityAgentPlannerUnavailable || transport.calls != 0 {
				t.Fatalf("invalid authority sent to provider: %+v calls%d", result, transport.calls)
			}
		})
	}
}
