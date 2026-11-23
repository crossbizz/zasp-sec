package apiserver

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAIControlsInstalledPolicyAndAudit(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("organization_admin", "manage_data_controls", "manage_identity", "view", "view_compliance")
	b.seed(func() {
		b.exec("INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES ($1,$2,$3,'production','metadata_only',30,true) ON CONFLICT DO NOTHING", b.o, b.w, b.e)
	})
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	handler := &identityHTTPHandler{administration: repo, now: time.Now}
	call := func(op, body, tag string, status int) *httptest.ResponseRecorder {
		t.Helper()
		defs := map[string]string{"getOrganizationAIControls": "/api/v1/organization/ai-controls", "updateOrganizationAIControls": "/api/v1/organization/ai-controls", "getEnvironmentAIControls": "/api/v1/settings/ai-controls", "updateEnvironmentAIControls": "/api/v1/settings/ai-controls", "listModelQualifications": "/api/v1/ai/qualifications", "getExternalDataFlows": "/api/v1/settings/external-data-flows", "getSystemStatus": "/api/v1/system/status"}
		method := "GET"
		if body != "" {
			method = "PATCH"
		}
		r := b.serve(handler, admin, op, method, defs[op], nil, body, map[string]string{"If-Match": tag})
		if r.Code != status {
			t.Fatalf("%s status %d (want %d): %s", op, r.Code, status, r.Body.String())
		}
		return r
	}
	assertValue := func(r *httptest.ResponseRecorder, key string, want any) {
		t.Helper()
		var row map[string]any
		if err := json.Unmarshal(r.Body.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if row["data"] != nil {
			row = row["data"].(map[string]any)
		}
		if row[key] != want {
			t.Fatalf("%s: got %v want %v (%s)", key, row[key], want, r.Body.String())
		}
	}
	assertValue(call("getOrganizationAIControls", "", "", 200), "ai_enabled", false)
	assertValue(call("getEnvironmentAIControls", "", "", 200), "effective_mode", "deterministic_only")
	call("listModelQualifications", "", "", 200)
	call("updateEnvironmentAIControls", `{"mode":"zasp_vpc_slm"}`, `"1"`, 400)
	call("updateOrganizationAIControls", `{"require_zero_retention":false}`, `"1"`, 400)
	org := call("updateOrganizationAIControls", `{"ai_enabled":true,"allowed_modes":["deterministic_only","zasp_vpc_slm","dev_openrouter"],"allowed_residency":"us_eu"}`, `"1"`, 200)
	assertValue(org, "version", float64(2))
	for _, body := range []string{`{"mode":"dev_openrouter"}`, `{"allow_approved_code_snippets":true}`, `{"tier2_purpose_drift_enabled":true}`, `{"mode":"zasp_vpc_slm","tier2_purpose_drift_enabled":true,"tier2_profile":"untested"}`, `{"monthly_budget_nano_credits":1.2}`, `{"organization_id":"other"}`} {
		call("updateEnvironmentAIControls", body, `"1"`, 400)
	}
	env := call("updateEnvironmentAIControls", `{"mode":"zasp_vpc_slm","allow_redacted_summaries":true,"monthly_budget_nano_credits":10}`, `"1"`, 200)
	assertValue(env, "effective_mode", "zasp_vpc_slm")
	call("updateEnvironmentAIControls", `{"monthly_budget_nano_credits":8}`, `"1"`, 409)
	b.seed(func() {
		b.exec("INSERT INTO public.model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,evidence_digest,deployment_digest,expires_at) VALUES($1,$2,$3,'zasp_vpc_slm','mistralai/Shieldstral-1.0-3B','purpose_alignment_check',true,$4,$4,now()+interval '7 days')", b.o, b.w, b.e, "sha256:"+strings.Repeat("a", 64))
	})
	call("updateEnvironmentAIControls", `{"tier2_profile":"mistralai/Shieldstral-1.0-3B","tier2_purpose_drift_enabled":true}`, `"2"`, 200)
	flow := call("getExternalDataFlows", "", "", 200).Body.String()
	if !strings.Contains(flow, "zasp_vpc_slm") || !strings.Contains(flow, `"health":"unknown"`) || !strings.Contains(flow, "redacted_summary") {
		t.Fatalf("unobserved private flow: %s", flow)
	}
	assertValue(call("getSystemStatus", "", "", 200), "optional_degraded", true)
	call("updateOrganizationAIControls", `{"ai_enabled":false}`, `"2"`, 200)
	assertValue(call("getEnvironmentAIControls", "", "", 200), "effective_mode", "deterministic_only")
	if s := call("getExternalDataFlows", "", "", 200).Body.String(); strings.Contains(s, "zasp_vpc_slm") {
		t.Fatal(s)
	}
	if got := b.text("SELECT count(*)::text FROM public.zasp_admin_audit WHERE organization_id=$1 AND action IN('updateOrganizationAIControls','updateEnvironmentAIControls')", b.o); got != "4" {
		t.Fatalf("audit count %s", got)
	}
	if _, err := b.fenced("zasp_svc_api", admin, RoutedOperation{OperationID: "getEnvironmentAIControls"}, aiControlsReadSQL, b.o, b.w, b.id(), "getEnvironmentAIControls"); err == nil {
		t.Fatal("cross-environment policy read")
	}
}

func TestV3PricingProvidersUseTheirOwnLedger(t *testing.T) {
	id := fixtureRequestIdentity(t)
	policy := securityAgentPricingPolicyFixture(id)
	org, w, e := id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), id.Scope.EnvironmentID().String()
	for _, provider := range []string{"zasp_vpc_slm", "bedrock_privatelink", "vertex_privatelink", "byoc_vllm", "openrouter", "unknown"} {
		for _, unit := range []string{"model_credit", "openrouter_credit"} {
			policy.Provider, policy.CostUnit = provider, unit
			want := provider == "openrouter" && unit == "openrouter_credit" || provider != "openrouter" && provider != "unknown" && unit == "model_credit"
			if got := validSecurityAgentPricingPolicy(policy, org, w, e); got != want {
				t.Errorf("provider %s with unit %s: got %v, want %v", provider, unit, got, want)
			}
		}
	}
}

func TestPrivatePlannerPricingInstalled(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("organization_admin", "manage_identity", "view")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewSecurityAgentPricingHTTPHandler(repo, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	submit := func(provider, unit, key string, want int) {
		t.Helper()
		policy := securityAgentPricingPolicyFixture(admin.identity)
		policy.Provider, policy.CostUnit = provider, unit
		now := time.Now().UTC()
		policy.EffectiveAt = now.Add(-time.Minute).Format(securityAgentPricingTimeLayout)
		policy.ExpiresAt = now.Add(time.Hour).Format(securityAgentPricingTimeLayout)
		raw, _ := json.Marshal(map[string]any{"environment_id": b.e, "operation": "create", "expected_account_version": 0, "policy": policy})
		response := b.serve(handler, admin, "setSecurityAgentPlannerPricing", "PUT", "/api/v1/security-agent-planner-pricing", nil, string(raw), map[string]string{"If-Match": `"0"`, "Idempotency-Key": key, "X-Zasp-Fresh-Auth": "confirmed"})
		if response.Code != want {
			t.Fatalf("%s = %d (%s), want %d", provider, response.Code, response.Body.String(), want)
		}
	}
	submit("bedrock_privatelink", "model_credit", "pricing-v3-bedrock-01", 200)
	submit("openrouter", "openrouter_credit", "pricing-v3-router-001", 400)
}
