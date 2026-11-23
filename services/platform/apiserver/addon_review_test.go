package apiserver

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

func addonTestReport(environment, digest string) string {
	return `{"schema_version":"zasp-addon-findings.v1","environment_id":"` + environment + `","ruleset":"zasp-static.v1","manifest_method":"addon-manifest.v1","manifest_digest":` + digest + `,"completeness":"complete","origin":"local","findings":[{"rule_id":"script.network_access","count":1}],"skipped_count":0}`
}

func TestAddonFindingAdmission(t *testing.T) {
	digest := `"sha256:` + strings.Repeat("a", 64) + `"`
	report := addonTestReport(automaticSourceID(1), digest)
	for _, tc := range []struct {
		name, raw string
		ok        bool
	}{
		{"complete", report, true},
		{"v2 executable", strings.ReplaceAll(strings.Replace(report, "zasp-static.v1", "zasp-static.v2", 1), "script.network_access", "script.remote_exec_pipe"), true},
		{"v2 rule on historical v1", strings.ReplaceAll(report, "script.network_access", "script.remote_exec_pipe"), false},
		{"unsupported ruleset", strings.Replace(report, "zasp-static.v1", "zasp-static.v20", 1), false}, {"missing complete bytes", strings.Replace(report, digest, "null", 1), false},
		{"partial with digest", strings.Replace(report, "complete\"", "partial\"", 1), false},
		{"uncounted", strings.Replace(report, `"count":1`, `"count":0`, 1), false},
		{"contaminated report", strings.Replace(report, `"ruleset":`, `"raw_source":"anything","ruleset":`, 1), false},
		{"unverified origin", strings.Replace(report, `"local"`, `"verified"`, 1), false},
		{"free form rule", strings.Replace(report, "script.network_access", "not-a-rule", 1), false},
		{"missing digest field", strings.Replace(report, `"manifest_digest":`+digest+`,`, "", 1), false},
		{"alias", strings.Replace(report, `"origin":`, `"Origin":`, 1), false},
		{"duplicate report field", strings.Replace(report, `"origin":`, `"origin":"ci","origin":`, 1), false},
		{"nested duplicate count", strings.Replace(report, `"count":1`, `"count":2,"count":1`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s addonSubmission
			valid := json.Unmarshal([]byte(tc.raw), &s) == nil && s.valid()
			if valid != tc.ok {
				t.Fatalf("valid=%v; want %v", valid, tc.ok)
			}
		})
	}
}

// The normal authorized request transaction, SQL capability fences, scoped PAT,
// and installed Postgres schema are exercised together. Only OpenFGA's remote
// checker is replaced by the existing release fixture.
func TestAddonRegistryOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issue, rawTokens := installedWorkloadTokenIssuer(t, b, repo, admin)
	machine := issue("Local addon report", `["submit_addon_scans"]`)
	surface := &discoveryWorkflowSurface{addons: &addonReviewHandler{database: b.product, newProductID: func() (string, error) { return b.id(), nil }}}
	digest := `"sha256:` + strings.Repeat("a", 64) + `"`
	input := addonTestReport(b.e, digest)
	post := func(caller installedPrincipal, key, report string, want int) map[string]any {
		t.Helper()
		rec := b.serve(surface, caller, "submitAddonScan", http.MethodPost, "/api/v1/addon-scans", nil, report, map[string]string{"Idempotency-Key": key})
		if rec.Code != want {
			t.Fatalf("submit want %d got %d %s", want, rec.Code, rec.Body.String())
		}
		var v map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	key := "first-addon-scan-" + b.id()
	v := post(machine, key, input, 200)
	id, ok := v["version_id"].(string)
	if !ok || !validProductID(id) || v["review_path"] != "/inventory/tools?addon="+id {
		t.Fatalf("receipt %v", v)
	}
	if repeat := post(machine, key, input, 200); repeat["scan_id"] != v["scan_id"] {
		t.Fatal("retry issued a new receipt")
	}
	post(machine, key, strings.Replace(input, "script.network_access", "dependency.unpinned", 1), 409)
	// A fresh idempotency key must not replace or silently contradict the
	// immutable findings for this origin, credential, ruleset and digest.
	mismatchKey := "conflicting-projection-" + b.id()
	post(machine, mismatchKey, strings.Replace(input, `"count":1`, `"count":2`, 1), 409)
	matched := post(machine, mismatchKey, input, 200)
	if matched["version_id"] != id || matched["scan_id"] == v["scan_id"] {
		t.Fatal("identical new report lost exact version identity")
	}
	if replay := post(machine, mismatchKey, input, 200); replay["scan_id"] != matched["scan_id"] {
		t.Fatal("matching report lost its idempotency receipt")
	}
	post(machine, "bad-environment-"+b.id(), strings.Replace(input, b.e, b.id(), 1), 400)
	post(machine, "bad-privacy-fields-"+b.id(), strings.Replace(input, `"origin":`, `"raw_source":"fake","origin":`, 1), 400)
	partial := strings.Replace(strings.Replace(input, digest, "null", 1), `"complete"`, `"partial"`, 1)
	pv := post(machine, "incomplete-scan-"+b.id(), partial, 200)
	if pv["version_id"] != nil || pv["review_path"] != nil {
		t.Fatal("partial scan became reviewable")
	}
	route := map[string]string{"id": id}
	path := "/api/v1/addon-versions/" + id
	check := func(principal installedPrincipal, op, method, url string, params map[string]string, body string, headers map[string]string, want int) map[string]any {
		t.Helper()
		res := b.serve(surface, principal, op, method, url, params, body, headers)
		if res.Code != want {
			t.Fatalf("%s want %d got %d %s", op, want, res.Code, res.Body.String())
		}
		var v map[string]any
		if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	partialID := pv["scan_id"].(string)
	observed := check(admin, "getAddonScan", "GET", "/api/v1/addon-scans/"+partialID, map[string]string{"id": partialID}, "", nil, 200)
	if observed["completeness"] != "partial" || observed["manifest_digest"] != nil || observed["version_id"] != nil {
		t.Fatal("partial scan became an approved version")
	}
	before := check(admin, "getAddonVersion", "GET", path, route, "", nil, 200)
	if before["revision"] != float64(0) || before["provenance"] != "reported" {
		t.Fatalf("detail %v", before)
	}
	expected := map[string]string{"If-Match": "\"0\"", "Idempotency-Key": "review-local-report-" + b.id()}
	review := func(headers map[string]string, state string, want int) map[string]any {
		return check(admin, "reviewAddonVersion", "POST", path+"/review-decisions", route, `{"state":"`+state+`"}`, headers, want)
	}
	if after := review(expected, "approved", 200); after["revision"] != float64(1) || after["review_state"] != "approved" {
		t.Fatalf("review %v", after)
	}
	review(expected, "approved", 200)
	review(expected, "revoked", 409)
	expected["Idempotency-Key"] = "second-review-key-" + b.id()
	review(expected, "revoked", 409)
	expected["If-Match"] = "\"1\""
	review(expected, "revoked", 200)
	editedInput := strings.Replace(input, strings.Repeat("a", 64), strings.Repeat("b", 64), 1)
	editedInput = strings.Replace(editedInput, "script.network_access", "dependency.unpinned", 1)
	edited := post(machine, "edited-addon-bytes-"+b.id(), editedInput, 200)
	if edited["version_id"] == id {
		t.Fatal("edited bytes retained the previous approval")
	}
	editedID := edited["version_id"].(string)
	exact := check(admin, "getAddonVersion", "GET", "/api/v1/addon-versions/"+editedID, map[string]string{"id": editedID}, "", nil, 200)
	foundReference := false
	for _, rawRef := range exact["framework_evidence"].([]any) {
		ref := rawRef.(map[string]any)
		if ref["framework"] == "owasp_agentic_top10" && ref["edition"] == "2026" && ref["upstream_id"] == "ASI04" && ref["rule_id"] == "dependency.unpinned" && ref["rule_version"] == "zasp-static.v1" && ref["evidence_kind"] == "static_scan" {
			foundReference = true
		}
	}
	if !foundReference || exact["manifest_digest"] != edited["manifest_digest"] || exact["review_state"] != "pending" {
		t.Fatalf("edited version lacks protected static evidence: %v", exact)
	}
	post(machine, "forged-addon-mapping-"+b.id(), strings.Replace(editedInput, `"count":1`, `"count":1,"framework_evidence":["ASI04"]`, 1), 400)
	page := check(admin, "listAddonVersions", "GET", "/api/v1/addon-versions?limit=1", nil, "", nil, 200)
	cursor, _ := page["next_cursor"].(string)
	if cursor != edited["version_id"] {
		t.Fatalf("newest page %v", page)
	}
	page = check(admin, "listAddonVersions", "GET", "/api/v1/addon-versions?limit=1&cursor="+cursor, nil, "", nil, 200)
	if page["next_cursor"] != nil || len(page["items"].([]any)) != 1 {
		t.Fatalf("older page %v", page)
	}
	stranger := b.id()
	check(admin, "getAddonVersion", "GET", "/api/v1/addon-versions/"+stranger, map[string]string{"id": stranger}, "", nil, 404)
	if _, err := b.checked(machine, RoutedOperation{OperationID: "getAddonVersion", PathParameters: route}); err == nil {
		t.Fatal("submitter gained read access")
	}
	if _, err := b.checked(machine, RoutedOperation{OperationID: "reviewAddonVersion", PathParameters: route}); err == nil {
		t.Fatal("submitter gained approval access")
	}
	if _, err := b.fenced("zasp_svc_api", admin, RoutedOperation{OperationID: "getAddonVersion", PathParameters: route}, addonVersionSQL, b.o, b.w, b.id(), id); installedSQLState(err) != "42501" {
		t.Fatalf("cross-Environment read returned %v", err)
	}
	if runtime.GOOS == "linux" {
		exerciseAddonCLIReview(t, b, repo, surface, admin, rawTokens["Local addon report"])
	}

}
