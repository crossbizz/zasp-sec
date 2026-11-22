package apiserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func TestEndpointPretoolCohortOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issue, _ := installedWorkloadTokenIssuer(t, b, repo, admin)
	token := issue("Pretool device", `["sync_endpoint"]`)
	h := endpointFleetHandler{database: b.product, newID: newWorkflowProductID, clock: time.Now}
	surface := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		h.serve(w, r, op)
	})
	req := func(actor installedPrincipal, op, method, path string, params map[string]string, v any, headers map[string]string, want int) map[string]any {
		t.Helper()
		var raw []byte
		if v != nil {
			raw, _ = json.Marshal(v)
		}
		res := b.serve(surface, actor, op, method, path, params, string(raw), headers)
		if res.Code != want {
			t.Fatalf("%s got %d want %d, %s", op, res.Code, want, res.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(res.Body.Bytes(), &out)
		return out
	}
	cohort := "engineering"
	root := "/api/v1/device-cohorts/" + cohort + "/pretool-policy"
	c := map[string]string{"cohort": cohort}
	key := func() map[string]string { return map[string]string{"Idempotency-Key": "pretool-" + b.id()} }
	if initial := req(admin, "getEndpointPolicyCohort", "GET", root, c, nil, nil, 200); initial["revision"] != float64(0) {
		t.Fatal(initial)
	}
	rules := []endpointprotocol.PretoolRule{{Type: "file_path_policy", ID: "sensitive-file", Values: []string{"ssh", "aws"}}}
	template := map[string]any{"mode": "enforce", "failure_mode": "closed", "expected_revision": 0, "rules": rules}
	idem := key()
	save := func(headers map[string]string, want int) map[string]any {
		return req(admin, "updateEndpointPolicyCohort", "PUT", root, c, template, headers, want)
	}
	if r := save(idem, 200); r["revision"] != float64(1) {
		t.Fatal(r)
	}
	save(idem, 200)
	save(key(), 409)
	template["mode"] = "monitor"
	save(idem, 409)
	template["mode"] = "enforce"
	if _, err := b.checked(token, RoutedOperation{OperationID: "updateEndpointPolicyCohort", PathParameters: c}); err == nil {
		t.Fatal("device transport credential may edit policy templates")
	}
	pub, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	issuer, signer, _ := ed25519.GenerateKey(rand.Reader)
	reg := req(admin, "registerEndpointDevice", "POST", "/api/v1/device-enrollments", nil, endpointRegister{Credential: token.binding.ID, DeviceKey: pub, PolicyKey: issuer, Cohort: cohort}, key(), 200)
	id := reg["id"].(string)
	params := map[string]string{"id": id}
	base := "/api/v1/devices/" + id
	binding := endpointprotocol.Binding{Organization: b.o, Workspace: b.w, Environment: b.e, Device: id, Generation: 1}
	signed := func(v any, private ed25519.PrivateKey) endpointprotocol.Signed {
		raw, _ := json.Marshal(v)
		return endpointprotocol.Signed{Payload: raw, Signature: ed25519.Sign(private, raw)}
	}
	machine := func(op, method, path string, p map[string]string, v any, want int) map[string]any {
		t.Helper()
		var raw []byte
		if v != nil {
			raw, _ = json.Marshal(v)
		}
		headers := http.Header{}
		if err := endpointprotocol.Sign(headers, binding, op, raw, deviceKey, time.Now()); err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for k := range headers {
			m[k] = headers.Get(k)
		}
		return req(token, op, method, path, p, v, m, want)
	}
	machine("exchangeEndpointEnrollment", "POST", "/api/v1/device-enrollments/exchange", nil, struct{}{}, 200)
	now := time.Now().UTC()
	policy := endpointprotocol.PolicyV2{Audience: endpointprotocol.PolicyAudienceV2, Binding: binding, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Mode: "monitor", FailureMode: "closed", Rules: rules}
	publish := func(bundle endpointprotocol.Signed, want int) {
		headers := key()
		headers["If-Match"] = `"1"`
		req(admin, "publishEndpointPolicy", "PUT", base+"/policy-bundle", params, bundle, headers, want)
	}
	publish(signed(policy, signer), 409)
	policy.Mode = "enforce"
	publish(signed(policy, deviceKey), 400)
	bundle := signed(policy, signer)
	publish(bundle, 200)
	fetched := machine("fetchEndpointPolicy", "GET", base+"/policy-bundle", params, nil, 200)
	raw, _ := json.Marshal(fetched["bundle"])
	var assigned endpointprotocol.Signed
	if json.Unmarshal(raw, &assigned) != nil {
		t.Fatal(fetched)
	}
	if _, ok := assigned.PolicyV2For(issuer, binding, now); !ok {
		t.Fatal("wrong assigned policy")
	}
	machine("recordEndpointHeartbeat", "POST", base+"/heartbeat", params, endpointprotocol.Heartbeat{Revision: 1, Adapter: "macos_codex_pretool_v2", PolicyStatus: "verified_cache"}, 200)
	obs := endpointprotocol.ObservationV2{Audience: endpointprotocol.ReceiptAudienceV2, Binding: binding, Action: strings.Repeat("e", 64), Session: strings.Repeat("b", 64), ObservedAt: now, PolicyRevision: 1, Mode: "enforce", Adapter: "macos_codex_pretool_v2", Tool: "file", RuleID: "sensitive-file", Reason: "ssh", Verdict: "deny", WouldBlock: true, TargetClass: "unknown", SkillUsage: "unknown", TargetEffect: "unknown"}
	report := func(o endpointprotocol.ObservationV2, p ed25519.PrivateKey, want int) {
		machine("recordEndpointObservations", "POST", "/api/v1/runtime/observations", nil, map[string]any{"receipts": []endpointprotocol.Signed{signed(o, p)}}, want)
	}
	report(obs, signer, 400)
	report(obs, deviceKey, 200)
	report(obs, deviceKey, 200)
	detail := req(admin, "getEndpointDevice", "GET", base, params, nil, nil, 200)
	receipts := detail["recent_observations"].([]any)
	if len(receipts) != 1 || detail["acknowledged"] != true {
		t.Fatal(detail)
	}
	row := receipts[0].(map[string]any)
	if row["rule_id"] != obs.RuleID || row["reason_code"] != "ssh" || row["target_effect"] != "unknown" {
		t.Fatal(row)
	}
	// A separately enrolled Windows machine independently acknowledges the same
	// cohort and produces a scoped observation. Its admin detail must never pick
	// up receipts from the previously exercised Mac.
	token = issue("Windows pretool device", `["sync_endpoint"]`)
	pub, deviceKey, _ = ed25519.GenerateKey(rand.Reader)
	reg = req(admin, "registerEndpointDevice", "POST", "/api/v1/device-enrollments", nil, endpointRegister{Credential: token.binding.ID, DeviceKey: pub, PolicyKey: issuer, Cohort: cohort}, key(), 200)
	id = reg["id"].(string)
	params = map[string]string{"id": id}
	base = "/api/v1/devices/" + id
	binding.Device = id
	policy.Binding = binding
	machine("exchangeEndpointEnrollment", "POST", "/api/v1/device-enrollments/exchange", nil, struct{}{}, 200)
	publish(signed(policy, signer), 200)
	unavailable := endpointprotocol.Heartbeat{Adapter: "windows_claude_pretool_v2", PolicyStatus: "state_unavailable"}
	machine("recordEndpointHeartbeat", "POST", base+"/heartbeat", params, unavailable, 200)
	if early := req(admin, "getEndpointDevice", "GET", base, params, nil, nil, 200); early["acknowledged"] != false {
		t.Fatal(early)
	}
	machine("recordEndpointHeartbeat", "POST", base+"/heartbeat", params, endpointprotocol.Heartbeat{Adapter: "windows_claude_pretool_v2", PolicyStatus: "verified_cache", Revision: 1}, 200)
	obs.Binding = binding
	obs.Action = strings.Repeat("a", 64)
	obs.Adapter = "windows_claude_pretool_v2"
	report(obs, deviceKey, 200)
	report(obs, deviceKey, 200)
	windowsDetail := req(admin, "getEndpointDevice", "GET", base, params, nil, nil, 200)
	if windowsDetail["acknowledged"] != true || windowsDetail["reported_adapter"] != obs.Adapter || windowsDetail["observation_count"] != float64(1) {
		t.Fatal(windowsDetail)
	}
	windowsRows := windowsDetail["recent_observations"].([]any)
	if len(windowsRows) != 1 {
		t.Fatal(windowsRows)
	}
	win := windowsRows[0].(map[string]any)
	if win["action_id"] != obs.Action || win["rule_id"] != obs.RuleID || win["target_effect"] != "unknown" {
		t.Fatal(win)
	}

}
