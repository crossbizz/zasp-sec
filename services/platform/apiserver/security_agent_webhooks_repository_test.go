package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

func TestSecurityAgentWebhookRepositoryClosedStatus(t *testing.T) {
	const id = "pid_9a590001-0000-4000-8000-000000000001"
	valid := `{"delivery_id":"` + id + `","run_id":"` + id + `","step_id":"` + id + `","destination_integration_id":"` + id + `","destination_integration_version":1,"payload_digest":"sha256:` + strings.Repeat("a", 64) + `","selection_digest":"sha256:` + strings.Repeat("b", 64) + `","signing_version":"` + strings.Repeat("c", 32) + `","state":"prepared","error_code":"","acknowledged_at":null,"receiver_verification":"unproven"}`
	if _, err := decodeResponseWebhookStatus(json.RawMessage(valid)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"url":            strings.Replace(valid, `"state":`, `"destination_url":"https://private.invalid","state":`, 1),
		"duplicate":      strings.Replace(valid, `"state":`, `"state":"acknowledged","state":`, 1),
		"alias":          strings.Replace(valid, `"delivery_id":`, `"Delivery_ID":`, 1),
		"null-error":     strings.Replace(valid, `"error_code":""`, `"error_code":null`, 1),
		"false-ack":      strings.Replace(valid, `"state":"prepared"`, `"state":"acknowledged"`, 1),
		"false-error":    strings.Replace(valid, `"error_code":""`, `"error_code":"secret_unavailable"`, 1),
		"empty-failure":  strings.Replace(valid, `"state":"prepared"`, `"state":"failed"`, 1),
		"receiver-claim": strings.Replace(valid, `"unproven"`, `"verified"`, 1),
		"version":        strings.Replace(valid, `"destination_integration_version":1`, `"destination_integration_version":1e0`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeResponseWebhookStatus(json.RawMessage(raw)); err != ErrRepositoryUnavailable {
				t.Fatalf("unsafe public status accepted: %v", err)
			}
		})
	}
}

func TestSecurityAgentWebhookRepositoryClaimDigestBinding(t *testing.T) {
	const id = "pid_9a590001-0000-4000-8000-000000000001"
	evidence := []securityagent.ResponseWebhookEvidence{{SourceKind: "manual", SourceID: strings.Repeat("a", 64), SourceVersion: 1, AssociationDigest: "sha256:" + strings.Repeat("b", 64)}}
	payload, digest, err := securityagent.EncodeResponseWebhookPayload(securityagent.ResponseWebhookPayload{SchemaVersion: 1, Type: "security_agent.response", DeliveryID: id, OrganizationID: id, WorkspaceID: id, EnvironmentID: id, RunID: id, StepID: id, PlanHash: "sha256:" + strings.Repeat("c", 64), Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	selection, _ := json.Marshal(evidence)
	selectionDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(selection))
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprint(wrong), func(t *testing.T) {
			selected := selectionDigest
			if wrong {
				selected = "sha256:" + strings.Repeat("d", 64)
			}
			wire, _ := json.Marshal(map[string]any{"organization_id": id, "workspace_id": id, "environment_id": id, "delivery_id": id, "token": "lease-token-00000001", "generation": 1, "expires_at": time.Now().UTC().Add(time.Minute), "destination_url": "https://hooks.example.test/response", "secret_reference": "secret_ref_response", "signing_version": strings.Repeat("a", 32), "payload": string(payload), "payload_digest": digest, "selection_digest": selected, "run_id": id, "step_id": id})
			r, _ := NewSecurityAgentWebhooksRepository(&exportSettlementDatabase{response: wire})
			_, found, err := r.ClaimResponseWebhook(context.Background())
			if (err == nil && !wrong) != (!wrong) || wrong && (err == nil || found) {
				t.Fatalf("wrong=%v found=%v err=%v", wrong, found, err)
			}
		})
	}
}

func TestSecurityAgentWebhookRepositoryRefusesMalformedBoundsBeforeSQL(t *testing.T) {
	db := &exportSettlementDatabase{}
	repository, err := NewSecurityAgentWebhooksRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{-1, 0, 101} {
		if _, err := repository.ExpireResponseWebhooks(context.Background(), limit); err != ErrRepositoryOperation {
			t.Fatal("expiry bound accepted", limit, err)
		}
	}
	for _, limit := range []int{-1, 0, 26} {
		if _, err := repository.ClaimResponseWebhookSettlements(context.Background(), "worker", "settlement-token-0001", 30, limit); err != ErrRepositoryOperation {
			t.Fatal("settlement bound accepted", limit, err)
		}
	}
	if _, err := repository.GetResponseWebhook(context.Background(), ResponseWebhookRead{}); err != ErrRepositoryOperation {
		t.Fatal("missing authority accepted", err)
	}
	if db.statement != "" {
		t.Fatal("invalid authority reached SQL")
	}
	db.response = json.RawMessage(`null`)
	if _, found, err := repository.ClaimResponseWebhook(context.Background()); err != nil || found {
		t.Fatalf("no-work result found=%v err=%v", found, err)
	}
	if db.statement != `SELECT public.zasp_claim_security_agent_webhook()` || len(db.args) != 0 {
		t.Fatal("dispatch claim took caller tenant authority")
	}
}

func TestSecurityAgentWebhookRepositoryHandoffSettlement(t *testing.T) {
	const id = "pid_9a590001-0000-4000-8000-000000000001"
	claim := ResponseWebhookSettlementClaim{Scope: ResponseWebhookScope{id, id, id}, DeliveryID: id, RunID: id, StepID: id, Token: "settlement-token-0001", Generation: 1, ExpiresAt: time.Now().Add(time.Minute), State: "acknowledged"}
	valid := `{"delivery_id":"` + id + `","run_id":"` + id + `","step_id":"` + id + `","state":"needs_human","delivery_state":"acknowledged","outcome_id":"` + id + `","reason":"webhook_handoff_acknowledged"}`
	for name, raw := range map[string]string{"valid": valid, "bare": strings.Replace(valid, `,"reason":"webhook_handoff_acknowledged"`, "", 1), "false-success": strings.Replace(valid, `"needs_human"`, `"succeeded"`, 1), "false-remediation": strings.Replace(valid, `"needs_human"`, `"remediated"`, 1), "wrong-reason": strings.Replace(valid, "webhook_handoff_acknowledged", "webhook_verified", 1)} {
		t.Run(name, func(t *testing.T) {
			db := &exportSettlementDatabase{response: json.RawMessage(raw)}
			r, _ := NewSecurityAgentWebhooksRepository(db)
			_, err := r.SettleResponseWebhookParent(context.Background(), claim, "worker", id, id, id)
			if (err == nil) != (name == "valid") {
				t.Fatalf("settlement err=%v", err)
			}
		})
	}
}

func TestSecurityAgentWebhookRepositoryPreservedSettlement(t *testing.T) {
	const id = "pid_9a590001-0000-4000-8000-000000000001"
	for _, tc := range []struct {
		state, delivery, reason string
		valid                   bool
	}{
		{"needs_human", "cancelled", "webhook_parent_outcome_preserved", true},
		{"failed", "cancelled", "webhook_parent_outcome_preserved", true},
		{"queued", "cancelled", "webhook_parent_outcome_preserved", false},
		{"succeeded", "cancelled", "webhook_parent_outcome_preserved", false},
		{"needs_human", "acknowledged", "webhook_parent_outcome_preserved", false},
		{"needs_human", "cancelled", "webhook_parent_cancelled", false},
		{"needs_human", "cancelled", "", false},
	} {
		claim := ResponseWebhookSettlementClaim{Scope: ResponseWebhookScope{id, id, id}, DeliveryID: id, RunID: id, StepID: id, Token: "settlement-token-0001", Generation: 1, State: tc.delivery}
		raw, _ := json.Marshal(ResponseWebhookSettlementResult{DeliveryID: id, RunID: id, StepID: id, State: tc.state, DeliveryState: tc.delivery, OutcomeID: id, Reason: tc.reason})
		r, _ := NewSecurityAgentWebhooksRepository(&exportSettlementDatabase{response: raw})
		if _, err := r.SettleResponseWebhookParent(context.Background(), claim, "worker", id, id, id); (err == nil) != tc.valid {
			t.Errorf("preserved %+v error=%v", tc, err)
		}
	}
}

func TestSecurityAgentWebhookIntegrationSigningVersion(t *testing.T) {
	for _, tc := range []struct {
		name, version  string
		present, valid bool
	}{
		{"legacy", "", false, true},
		{"pinned", strings.Repeat("a", 32), true, true},
		{"maximum", strings.Repeat("9", 64), true, true},
		{"empty", "", true, false},
		{"short", "AWSCURRENT", true, false},
		{"path", strings.Repeat("a", 31) + "/", true, false},
		{"long", strings.Repeat("a", 65), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := newWorkflowHTTPHandler(&workflowRepositoryStub{}, []byte(strings.Repeat("k", 32)), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			config := map[string]string{"destination_url": "https://hooks.example.test/response", "signing_secret_reference": "secret_ref_response"}
			if tc.present {
				config["signing_secret_version"] = tc.version
			}
			raw, _ := json.Marshal(map[string]any{"connector_key": "generic-webhook", "name": "Response", "configuration": config})
			req := httptest.NewRequest("POST", "/api/v1/integrations", strings.NewReader(string(raw)))
			req.Header.Set("Content-Type", "application/json")
			body, _, err := handler.integrationBody(req, fixtureRequestIdentity(t).Scope, "", "response-version-test", true)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && tc.present {
				var value struct {
					Configuration map[string]string `json:"configuration"`
				}
				if json.Unmarshal(body, &value) != nil || value.Configuration["signing_secret_version"] != tc.version {
					t.Fatal("pinned version was not persisted")
				}
			}
		})
	}
}
