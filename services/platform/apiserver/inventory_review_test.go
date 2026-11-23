package apiserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

type reviewDriver struct {
	reply json.RawMessage
	calls int
}

func (d *reviewDriver) Evaluate(_ context.Context, _ aigateway.Purpose, _ json.RawMessage) (json.RawMessage, error) {
	d.calls++
	return d.reply, nil
}

func TestInventoryReviewCitationsCannotBeInvented(t *testing.T) {
	d := &reviewDriver{reply: json.RawMessage(`{"kind":"autonomous_agent","evidence_refs":["other"]}`)}
	facts := json.RawMessage(`{"signals":["package:openai"],"evidence_refs":["observed"],"tool_ids":[]}`)
	req := httptest.NewRequest("POST", "/", nil)
	if result := runInventoryReview(req, &analystChat{driver: d}, aigateway.PurposeDiscoveryVerify, facts); result != nil {
		t.Fatal(string(result))
	}
	d.reply = json.RawMessage(`{"kind":"simple_llm_app","evidence_refs":["observed"]}`)
	if result := runInventoryReview(req, &analystChat{driver: d}, aigateway.PurposeDiscoveryVerify, facts); result == nil {
		t.Fatal("supported citation lost")
	}
	d.reply = json.RawMessage(`{"allowed_tool_ids":["pid_11111111-1111-4111-8111-111111111111"],"iam_mismatches":[]}`)
	if result := runInventoryReview(req, &analystChat{driver: d}, aigateway.PurposeDraft, facts); result != nil {
		t.Fatal("unseen tool in purpose draft")
	}
}

func TestInventoryReviewDefaultsNeverDispatch(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	id := b.id()
	b.seed(func() {
		b.exec("INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind) VALUES($1,$2,$3,$4,'agent','registered','{}',now(),now(),'agent')", b.o, b.w, b.e, id)
	})
	d := &reviewDriver{}
	surface := &discoveryWorkflowSurface{evidenceDB: b.product, inventoryModels: map[string]*analystChat{"verifyAgentDiscovery": {driver: d}}}
	for _, op := range []string{"verifyAgentDiscovery", "draftAgentPurpose"} {
		r := b.serve(surface, admin, op, "POST", "/api/v1/agents/"+id+"/discovery/verify", map[string]string{"id": id}, "{}", map[string]string{"Idempotency-Key": b.id()})
		var receipt semanticReceipt
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &receipt) != nil || receipt.Degraded == nil || !*receipt.Degraded || string(receipt.Result) != "null" || d.calls != 0 {
			t.Fatalf("%s %d %s calls=%d", op, r.Code, r.Body.String(), d.calls)
		}
	}
}

func TestInventoryReviewQualifiedDispatchIsCitedAndBudgetedOnce(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	id, evidence := b.id(), b.id()
	cfg := aigateway.BedrockBinding{Provider: aigateway.ModeBedrock, Model: "anthropic.claude-sonnet-4-6", Region: "us", CredentialReference: "secret_ref_planner/" + b.o + "/" + b.w + "/" + b.e + "/v1", CredentialDigest: "sha256:" + strings.Repeat("a", 64), DeploymentDigest: "sha256:" + strings.Repeat("b", 64), Cost: 2}
	b.seed(func() {
		b.exec("INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind,winning_evidence_id,winning_attributes) VALUES($1,$2,$3,$4,'agent','registered','{}',now(),now(),'agent',$5,'{\"discovery\":{\"signals\":[\"layout:tool_schema\",\"package:openai\"],\"method\":\"inferred\"}}')", b.o, b.w, b.e, id, evidence)
		b.exec(`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,true) ON CONFLICT DO NOTHING`, b.o, b.w, b.e)
		b.exec(`INSERT INTO zasp_organization_ai_controls(organization_id,ai_enabled,allowed_modes,allowed_residency) VALUES($1,true,ARRAY['deterministic_only','privatelink_bedrock'],'us_only')`, b.o)
		b.exec(`INSERT INTO zasp_environment_ai_controls(organization_id,workspace_id,environment_id,environment_class,mode,tier3_provider,tier3_model_pin,tier3_discovery_purpose_enabled,allow_redacted_summaries,monthly_budget_nano_credits,credential_reference,credential_digest) VALUES($1,$2,$3,'production','privatelink_bedrock','privatelink_bedrock',$4,true,true,2,$5,$6)`, b.o, b.w, b.e, cfg.Model, cfg.CredentialReference, cfg.CredentialDigest)
		b.exec(`INSERT INTO model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,deployment_digest,evidence_digest,expires_at) VALUES($1,$2,$3,'privatelink_bedrock',$4,'agent_discovery_verify',true,$5,$5,now()+interval '1 hour')`, b.o, b.w, b.e, cfg.Model, cfg.DeploymentDigest)
	})
	d := &reviewDriver{reply: json.RawMessage(`{"kind":"autonomous_agent","evidence_refs":["` + evidence + `"]}`)}
	h := &discoveryWorkflowSurface{evidenceDB: b.product, inventoryModels: map[string]*analystChat{"verifyAgentDiscovery": {driver: d, binding: cfg}}}
	run := func(k string, degraded bool) {
		t.Helper()
		r := b.serve(h, admin, "verifyAgentDiscovery", "POST", "/api/v1/agents/"+id+"/discovery/verify", map[string]string{"id": id}, "{}", map[string]string{"Idempotency-Key": k})
		var rec semanticReceipt
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &rec) != nil || rec.Degraded == nil || *rec.Degraded != degraded {
			t.Fatalf("expected degraded=%t; got %d: %s", degraded, r.Code, r.Body.String())
		}
	}
	key := b.id()
	run(key, false)
	run(key, false)
	run(b.id(), true)
	if d.calls != 1 {
		t.Fatalf("model calls=%d", d.calls)
	}
}
