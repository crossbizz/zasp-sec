package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSecurityAgentManualReadPreservesNestedStrictness(t *testing.T) {
	approval, wire := approvalContextFixture("create_evidence_export")
	approval.ExpectedEffect = "Create run-scoped evidence export"
	_, _, pin, _ := agentDownloadFixture(t)
	wire["arguments"] = map[string]any{"target_id": approval.RunID, "evidence_ids": pin.Binding.Selection}
	raw, _ := json.Marshal(wire)
	var err error
	approval.Context, err = decodeSecurityAgentApprovalContext(raw, approval)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"valid", "context", "requester", "reason", "risk", "rationale", "selection"} {
		t.Run(path, func(t *testing.T) {
			var object map[string]any
			if json.Unmarshal(encoded, &object) != nil {
				t.Fatal("invalid fixture")
			}
			context := object["approval_context"].(map[string]any)
			switch path {
			case "valid":
			case "context":
				context["private"] = true
			case "selection":
				context["export_selection"].([]any)[0].(map[string]any)["storage_key"] = "private-sentinel"
			case "rationale":
				context["rationale"] = map[string]any{"state": "withheld", "summary": "", "private": true}
			default:
				context[path].(map[string]any)["private"] = true
			}
			changed, _ := json.Marshal(object)
			var decoded SecurityAgentApproval
			err := decodeStrictDiscovery(changed, &decoded)
			if path == "valid" {
				if err != nil || !validSecurityAgentApproval(decoded) {
					t.Fatalf("valid approval rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("nested unknown field was silently discarded")
			}
		})
	}
}

// The real detail reader must preserve manual identity without putting digest
// strings into ProductID evidence arrays, or accepting an unrelated approval.
func TestSecurityAgentManualReadBinding(t *testing.T) {
	digest := strings.Repeat("a", 64)
	manual := `{"kind":"manual","intent_digest":"sha256:` + digest + `","version":1}`
	run := `{"id":"` + runContextTestRunID + `","agent_id":"pid_78000001-0000-4000-8000-000000000001","state":"waiting_approval","evidence_ids":[],"definition_version":1,"version":4,"manual_trigger":` + manual + `}`
	approval := `{"id":"pid_78000008-0000-4000-8000-000000000008","run_id":"` + runContextTestRunID + `","step_id":"pid_78000007-0000-4000-8000-000000000007","state":"pending","expires_at":"2026-09-19T12:00:00Z","version":1,"expected_effect":"Create run-scoped evidence export","reversible":true,"ttl_seconds":0,"evidence_summary":[],"manual_trigger":` + manual + `}`
	detail := `{"run":` + run + `,"evidence_ids":[],"plan":{"plan_hash":"sha256:` + strings.Repeat("b", 64) + `","catalog_version":"security-agent-actions-v1","expires_at":"2026-09-19T12:00:00Z","steps":[{"id":"pid_78000007-0000-4000-8000-000000000007","index":0,"action":"create_evidence_export","authorization":"approval_required","state":"waiting_approval","version":1}]},"authorization":"approval_required","approvals":[` + approval + `],"execution":[{"step_id":"pid_78000007-0000-4000-8000-000000000007","action":"create_evidence_export","state":"waiting_approval","version":1}],"verification":"not_started"}`
	trigger := `{"kind":"manual","id":"` + digest + `","version":1}`
	for _, test := range []struct {
		name, detail, trigger string
		want                  bool
	}{
		{"valid manual", detail, trigger, true},
		{"wrong context digest", detail, strings.Replace(trigger, digest, strings.Repeat("c", 64), 1), false},
		{"wrong context version", detail, strings.Replace(trigger, `"version":1`, `"version":2`, 1), false},
		{"missing context trigger", detail, "null", false},
		{"duplicate context trigger kind", detail, strings.Replace(trigger, `"kind":`, `"kind":"manual","kind":`, 1), false},
		{"wrong context kind", detail, strings.Replace(trigger, "manual", "finding", 1), false},
		{"approval digest drift", strings.Replace(detail, approval, strings.Replace(approval, digest, strings.Repeat("c", 64), 1), 1), trigger, false},
		{"approval version drift", strings.Replace(detail, approval, strings.Replace(approval, `"manual_trigger":`+manual, `"manual_trigger":`+strings.Replace(manual, `"version":1`, `"version":2`, 1), 1), 1), trigger, false},
		{"mixed evidence", strings.Replace(detail, `"evidence_ids":[]`, `"evidence_ids":["pid_78000005-0000-4000-8000-000000000005"]`, 1), trigger, false},
		{"null evidence", strings.Replace(detail, `"evidence_ids":[]`, `"evidence_ids":null`, 1), trigger, false},
		{"null outer evidence", strings.Replace(detail, `},"evidence_ids":[]`, `},"evidence_ids":null`, 1), trigger, false},
		{"null provenance", strings.Replace(detail, `"manual_trigger":`+manual, `"manual_trigger":null`, 1), trigger, false},
		{"duplicate provenance", strings.Replace(detail, `"manual_trigger":`+manual, `"manual_trigger":`+manual+`,"manual_trigger":`+manual, 1), trigger, false},
		{"alias provenance", strings.Replace(detail, `"manual_trigger":`, `"Manual_trigger":`, 1), trigger, false},
		{"approval null evidence", strings.Replace(detail, `"evidence_summary":[]`, `"evidence_summary":null`, 1), trigger, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := `{"detail":` + test.detail + `,"context":{"trigger":` + test.trigger + `,"planner_receipt":null}}`
			result, err := decodeSecurityAgentRunContextEnvelope(json.RawMessage(payload), runContextTestRunID)
			if !test.want {
				if err == nil {
					t.Fatal("mismatched manual provenance accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("valid manual detail refused: %v", err)
			}
			encoded, err := json.Marshal(result.Run)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(encoded), `"manual_trigger":`+manual) || !strings.Contains(string(encoded), `"evidence_ids":[]`) {
				t.Fatalf("manual identity lost: %s", encoded)
			}
			response := runContextHTTP(t, result, []string{"v1"}, false)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"manual_trigger":`+manual) {
				t.Fatalf("manual read HTTP lost identity: status=%d", response.Code)
			}
			identity := fixtureRequestIdentity(t)
			identity.CredentialKind = CredentialBrowserSession
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
				postgresSecurityAgentRunPageSQL:        json.RawMessage(`{"items":[` + run + `],"next_created_at":null,"next_id":null}`),
				postgresSecurityAgentApprovalDetailSQL: json.RawMessage(approval),
			}}
			repository := &PostgresRepository{database: database, securityAgentExecution: true}
			page, err := repository.ListSecurityAgentRuns(context.Background(), identity, SecurityAgentRunPageRequest{Limit: 1})
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("manual run page refused: %v", err)
			}
			value, err := repository.GetSecurityAgentApproval(context.Background(), identity, "pid_78000008-0000-4000-8000-000000000008")
			if err != nil || !sameSecurityAgentManualTrigger(value.ManualTrigger, result.Run.ManualTrigger) {
				t.Fatalf("manual approval read refused or lost identity: %v", err)
			}
		})
	}
}
