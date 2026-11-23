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
	// A real evaluation makes the day dirty. On the next read the persisted
	// histogram includes the existing feedback; subsequent corrections update it.
	b.exec(`INSERT INTO public.semantic_evaluations VALUES($1,$2,$3,$4,$5,0.2,true,'sha256:'||repeat('a',64),now())`, b.o, b.w, b.e, decision, rule)
	if res := get(); res.Code != 200 {
		t.Fatal(res.Code, res.Body)
	}
	rollup := func() string {
		return b.text(`SELECT concat(n,'/',tn,'/',fn,'/',serious_positives) FROM public.calibration_daily_rollups WHERE (organization_id,workspace_id,environment_id,bucket)=($1,$2,$3,2)`, b.o, b.w, b.e)
	}
	if v := rollup(); v != "1/1/0/0" {
		t.Fatal("initial day", v)
	}
	if res := feedback("confirm_tp", "calibration-relabel-123"); res.Code != 200 {
		t.Fatal(res.Code, res.Body)
	}
	if res := get(); res.Code != 200 {
		t.Fatal(res.Code, res.Body)
	}
	if v := rollup(); v != "1/0/1/1" {
		t.Fatal("relabelled day", v)
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
