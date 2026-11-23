package apiserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

// Use a fixture classifier with a real scoped PAT and approved profile. The
// entire normal decision path, reservation, shadow receipt and cap are in PG.
func TestPrivateGuardrailShadowOnInstalledPostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	member := b.member("security_admin", "manage_api_tokens", "decide_guardrails")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issue, _ := installedWorkloadTokenIssuer(t, b, repo, member)
	pat := issue("Guardrail evaluator", `["decide_guardrails"]`)
	d := aigateway.Deployment{Model: aigateway.ModelShieldstral, PrivateIP: "10.0.0.2", Endpoint: "https://guardrail.example.test/v1/chat/completions", WeightsSHA256: strings.Repeat("a", 64), MaximumNanoCredits: 3, Region: "eu"}
	b.seed(func() {
		b.exec(`INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'staging','extended',30,false)`, b.o, b.w, b.e)
		b.exec(`INSERT INTO public.zasp_organization_ai_controls(organization_id,ai_enabled,allowed_modes,allowed_residency,allow_private_code_egress) VALUES($1,true,ARRAY['zasp_vpc_slm','deterministic_only'],'eu_only',true)`, b.o)
		b.exec(`INSERT INTO public.zasp_environment_ai_controls(organization_id,workspace_id,environment_id,environment_class,mode,tier2_profile,monthly_budget_nano_credits,allow_approved_code_snippets,tier2_heuristic_fp_suppression_enabled) VALUES($1,$2,$3,'staging','zasp_vpc_slm',$4,3,true,true)`, b.o, b.w, b.e, d.Model)
		b.exec(`INSERT INTO public.model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,deployment_digest,expires_at,evidence_digest) VALUES($1,$2,$3,'zasp_vpc_slm',$4,'heuristic_fp_verify',true,$5,now()+interval '1 day',$5)`, b.o, b.w, b.e, d.Model, d.Digest())
		b.exec(`INSERT INTO public.rule_suppression_states(organization_id,workspace_id,environment_id,rule_id,mode,version,actor) VALUES($1,$2,$3,'injection.tool_call','shadow',1,$4)`, b.o, b.w, b.e, member.identity.PrincipalID.String())
	})
	driver := &semanticTestDriver{}
	policy := guardrailHTTPHandler{database: b.product, newProductID: newWorkflowProductID, profiles: guardrailProfiles{aigateway.PurposeHeuristicVerify: {deployment: d, driver: driver}}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { policy.ServeHTTP(w, r, "createGuardrailDecision") })
	request := func(approved bool) GuardrailDecision {
		input := map[string]any{"direction": "input", "text": "The glossary includes the <tool_call> label."}
		if approved {
			input["content_mode"] = "approved_code_snippet"
		}
		raw, _ := json.Marshal(input)
		res := b.serve(h, pat, "createGuardrailDecision", "POST", "/api/v1/guardrails/decisions", nil, string(raw), nil)
		var decision GuardrailDecision
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &decision) != nil || decision.Decision != "block" {
			t.Fatal(res.Code, res.Body)
		}
		return decision
	}
	request(false)
	if driver.calls != 0 {
		t.Fatal("missing input consent")
	}
	observed := request(true)
	if driver.calls != 1 {
		t.Fatal("qualified call was not admitted")
	}
	if state := b.text(`SELECT semantic_state FROM public.zasp_guardrail_decisions WHERE id=$1`, observed.DecisionID); state != "shadow" {
		t.Fatal(state)
	}
	if n := b.text(`SELECT count(*)::text FROM public.semantic_evaluations WHERE decision_id=$1`, observed.DecisionID); n != "1" {
		t.Fatal("missing evaluation", n)
	}
	request(true)
	if driver.calls != 1 {
		t.Fatal("monthly budget exceeded")
	}
}
