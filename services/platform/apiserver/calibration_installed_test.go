package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCalibrationOnInstalledPostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	user := b.member("security_admin", "view", "manage_workflows")
	decision := b.id()
	const rule = "injection.tool_call"
	b.seed(func() {
		b.exec(`INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,false) ON CONFLICT DO NOTHING`, b.o, b.w, b.e)
		b.exec(`INSERT INTO public.zasp_guardrail_decisions(organization_id,workspace_id,environment_id,id,principal_id,direction,decision,rules,input_bytes,content_digest,policy_version) VALUES ($1,$2,$3,$4,'test','input','block','[{"id":"injection.tool_call"}]',4,decode(repeat('22',32),'hex'),0)`, b.o, b.w, b.e, decision)
	})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		serveCalibration(b.product, w, r, op)
	})
	get := func() *httptest.ResponseRecorder {
		return b.serve(h, user, "getCalibrationMetrics", "GET", "/api/v1/calibration/metrics", nil, "", nil)
	}
	metrics := get()
	if metrics.Code != 200 || !strings.Contains(metrics.Body.String(), decision) {
		t.Fatalf("initial metrics %d %s", metrics.Code, metrics.Body)
	}
	feedback := func(label, key string) *httptest.ResponseRecorder {
		return b.serve(h, user, "submitAnalystFeedback", "POST", "/api/v1/feedback", nil, `{"decision_id":"`+decision+`","rule_id":"injection.tool_call","label":"`+label+`"}`, map[string]string{"Idempotency-Key": key})
	}
	key := "label-calibration-sample-1"
	if res := feedback("mark_fp", key); res.Code != 200 {
		t.Fatal(res.Code, res.Body)
	}
	if res := feedback("mark_fp", key); res.Code != 200 {
		t.Fatal("replay", res.Code, res.Body)
	}
	if res := feedback("confirm_tp", key); res.Code != 409 {
		t.Fatal("key reuse", res.Code, res.Body)
	}
	metrics = get()
	var marked struct {
		Labelled int
		Recent   []recentMatch
		Brier    *float64
	}
	if metrics.Code != 200 || json.Unmarshal(metrics.Body.Bytes(), &marked) != nil || marked.Labelled != 1 || marked.Brier != nil || len(marked.Recent) != 1 || marked.Recent[0].Label == nil || *marked.Recent[0].Label != "mark_fp" {
		t.Fatal(metrics.Code, metrics.Body)
	}
	mode := func(id, value, match, key string) *httptest.ResponseRecorder {
		return b.serve(h, user, "putRuleSuppressionMode", "PUT", "/api/v1/rules/"+id+"/suppression-mode", map[string]string{"ruleId": id}, `{"mode":"`+value+`"}`, map[string]string{"Idempotency-Key": key, "If-Match": match})
	}
	if res := mode("pii.credit_card", "shadow", `"0"`, "hard-suppression-test"); res.Code != 400 {
		t.Fatal("hard rule", res.Code, res.Body)
	}
	if res := mode(rule, "shadow", `"0"`, "shadow-suppression-test"); res.Code != 200 || res.Header().Get("ETag") != `"1"` {
		t.Fatal(res.Code, res.Body)
	}
	if res := mode(rule, "active", `"1"`, "active-suppression-test"); res.Code != 400 {
		t.Fatal("unproven promotion", res.Code, res.Body)
	}
	if res := mode(rule, "off", `"0"`, "stale-suppression-test"); res.Code != 409 {
		t.Fatal("stale", res.Code, res.Body)
	}
}
