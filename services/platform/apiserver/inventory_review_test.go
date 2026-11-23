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
	cfg := enablePrivateDiscoveryFixture(t, b, 2)
	b.seed(func() {
		b.exec("INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind,winning_evidence_id,winning_attributes) VALUES($1,$2,$3,$4,'agent','registered','{}',now(),now(),'agent',$5,'{\"discovery\":{\"signals\":[\"layout:tool_schema\",\"package:openai\"],\"method\":\"inferred\"}}')", b.o, b.w, b.e, id, evidence)
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

func enablePrivateDiscoveryFixture(t *testing.T, b *installedBaseline, budget int) aigateway.BedrockBinding {
	t.Helper()
	cfg := aigateway.BedrockBinding{Provider: aigateway.ModeBedrock, Model: "anthropic.claude-sonnet-4-6", Region: "us", CredentialReference: "secret_ref_planner/" + b.o + "/" + b.w + "/" + b.e + "/v1", CredentialDigest: "sha256:" + strings.Repeat("a", 64), DeploymentDigest: "sha256:" + strings.Repeat("b", 64), Cost: 2}
	b.seed(func() {
		b.exec(`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,true) ON CONFLICT DO NOTHING`, b.o, b.w, b.e)
		b.exec(`INSERT INTO zasp_organization_ai_controls(organization_id,ai_enabled,allowed_modes,allowed_residency) VALUES($1,true,ARRAY['deterministic_only','privatelink_bedrock'],'us_only')`, b.o)
		b.exec(`INSERT INTO zasp_environment_ai_controls(organization_id,workspace_id,environment_id,environment_class,mode,tier3_provider,tier3_model_pin,tier3_discovery_purpose_enabled,allow_redacted_summaries,monthly_budget_nano_credits,credential_reference,credential_digest) VALUES($1,$2,$3,'production','privatelink_bedrock','privatelink_bedrock',$4,true,true,$7,$5,$6)`, b.o, b.w, b.e, cfg.Model, cfg.CredentialReference, cfg.CredentialDigest, budget)
		b.exec(`INSERT INTO model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,deployment_digest,evidence_digest,expires_at) VALUES($1,$2,$3,'privatelink_bedrock',$4,'agent_discovery_verify',true,$5,$5,now()+interval '1 hour')`, b.o, b.w, b.e, cfg.Model, cfg.DeploymentDigest)
	})
	return cfg
}

func TestSyncDiscoveryReviewQualifiesChargesAndCitesCurrentEvidence(t *testing.T) {
	b := startInstalledV2Baseline(t)
	cfg := enablePrivateDiscoveryFixture(t, b, 4)
	binding, _ := json.Marshal(cfg)
	const verify = "agent_discovery_verify"
	const draft = "agent_purpose_draft"
	id, ev, snapshot, integration := b.id(), b.id(), b.id(), b.id()
	b.seed(func() {
		b.exec("INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind,winning_provider) VALUES($1,$2,$3,$4,'agent','repository','{}',now(),now(),'agent','github')", b.o, b.w, b.e, id)
	})
	update := func(snapshot string) {
		b.exec(`UPDATE zasp_inventory_entities SET winning_integration_id=$5,winning_snapshot_id=$6,winning_evidence_id=$7,winning_attributes='{"discovery":{"method":"inferred","platform":"github_repository","signals":["layout:tool_schema","package:openai"]}}' WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, b.o, b.w, b.e, id, integration, snapshot, ev)
	}
	update(snapshot)
	update(snapshot)
	claim := func(p string) string {
		return b.text("SELECT public.zasp_claim_discovery_sync_review($1,$2::jsonb)->>'lease'", p, string(binding))
	}
	lease := claim(verify)
	if lease == "" || claim(verify) != "" {
		t.Fatal("expected one verification lease per snapshot")
	}
	if b.text("SELECT public.zasp_finish_discovery_sync_review($1::text::uuid,$2::jsonb)::text", lease, `{"kind":"autonomous_agent","evidence_refs":["`+ev+`"]}`) != "true" {
		t.Fatal("trusted cited result not accepted")
	}
	if claim(draft) != "" {
		t.Fatal("draft without a purpose-specific qualification")
	}
	b.seed(func() {
		b.exec(`INSERT INTO model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,deployment_digest,evidence_digest,expires_at) VALUES($1,$2,$3,'privatelink_bedrock',$4,'agent_purpose_draft',true,$5,$5,now()+interval '1 hour')`, b.o, b.w, b.e, cfg.Model, cfg.DeploymentDigest)
	})
	next := claim(draft)
	if next == "" {
		t.Fatal("qualified second phase not scheduled")
	}
	update(b.id())
	if b.text("SELECT public.zasp_finish_discovery_sync_review($1::text::uuid,$2::jsonb)::text", next, `{"allowed_tool_ids":[],"iam_mismatches":[]}`) != "false" {
		t.Fatal("draft from prior snapshot accepted")
	}
	if claim(verify) != "" {
		t.Fatal("over-budget verification dispatched")
	}
	if b.text("SELECT reserved_nano_credits::text FROM zasp_ai_monthly_usage WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)", b.o, b.w, b.e) != "4" {
		t.Fatal("unexpected reserved budget")
	}
	if b.text("SELECT has_function_privilege('zasp_discovery_api','public.zasp_claim_discovery_sync_review(text,jsonb)','execute')::text") != "false" {
		t.Fatal("API can lease background jobs")
	}
}

// Offline observations stay bound to a registered version. The semantic job
// receives only its indicator codes and evidence IDs, with no raw trace data.
func TestOfflineAddonObservationBindsVersionAndReviewCitations(t *testing.T) {
	b := startInstalledV2Baseline(t)
	id, ev, now := b.id(), b.id(), time.Now().UTC()
	digest := "sha256:" + strings.Repeat("c", 64)
	b.seed(func() {
		b.exec("INSERT INTO zasp_addon_versions(organization_id,workspace_id,environment_id,id,manifest_digest,origin,origin_credential,ruleset,findings,review_state) VALUES($1,$2,$3,$4,$5,'local',$6,'zasp-static.v2','[]','pending')", b.o, b.w, b.e, id, digest, b.id())
		b.exec("INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,true) ON CONFLICT DO NOTHING", b.o, b.w, b.e)
	})
	payload := map[string]any{"schema_version": "zasp-offline-addon-observation.v1", "organization_id": b.o, "workspace_id": b.w, "environment_id": b.e, "addon_version_id": id, "manifest_digest": digest, "evidence_id": ev, "scanner": "gvisor_tetragon", "scanner_profile_digest": digest, "isolation": "egress_denied", "observed_at": now.Add(-time.Minute), "expires_at": now.Add(time.Hour), "indicators": []string{"honeytoken_egress_denied"}}
	submit := func(want string) {
		t.Helper()
		raw, _ := json.Marshal(payload)
		if got := b.text("SELECT public.zasp_import_addon_observation($1::jsonb,$2)::text", string(raw), fmt.Sprintf("sha256:%x", sha256.Sum256(raw))); got != want {
			t.Fatalf("receipt acceptance=%s, expected %s", got, want)
		}
	}
	submit("true")
	submit("true")
	payload["manifest_digest"] = "sha256:" + strings.Repeat("b", 64)
	submit("false")
	payload["manifest_digest"] = digest
	payload["indicators"] = []string{"unexpected_process"}
	submit("false")
	raw := b.text("SELECT zasp_authorization80.inventory_review_summary($1,$2,$3,$4,'addon_semantic_audit')::text", b.o, b.w, b.e, id)
	var facts struct {
		Refs         []string `json:"evidence_refs"`
		Observations []struct {
			Evidence   string   `json:"evidence_id"`
			Indicators []string `json:"indicators"`
		} `json:"offline_observations"`
	}
	if json.Unmarshal([]byte(raw), &facts) != nil || len(facts.Refs) != 1 || facts.Refs[0] != ev || len(facts.Observations) != 1 || facts.Observations[0].Evidence != ev || len(facts.Observations[0].Indicators) != 1 || facts.Observations[0].Indicators[0] != "honeytoken_egress_denied" {
		t.Fatal(raw)
	}
	if b.text("SELECT has_function_privilege('zasp_discovery_api','public.zasp_import_addon_observation(jsonb,text)','execute')::text") != "false" {
		t.Fatal("public API can claim scanner observations")
	}
}
