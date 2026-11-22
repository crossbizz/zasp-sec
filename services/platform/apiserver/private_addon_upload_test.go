package apiserver

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPrivateAddonUploadOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	member := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	installedIdentityVerifiers(b)
	scope := strings.Join([]string{b.o, b.w, b.e}, "/")
	t.Setenv("ZASP_PRIVATE_ADDON_WORKER_SCOPE", scope)
	t.Setenv("ZASP_PRIVATE_ADDON_WORKER_ORIGIN", "https://private.example.invalid")
	h := &identityHTTPHandler{repository: repo, tokenRevealKey: bytes.Repeat([]byte{0x24}, 32), now: time.Now}
	digest := "sha256:" + strings.Repeat("b", 64)
	headers := map[string]string{"Idempotency-Key": "private-grant-" + b.id()}
	body := `{"mode":"private_upload","retention":"memory_only","archive_bytes":998,"archive_digest":"` + digest + `"}`
	call := func(payload string, want int) []byte {
		t.Helper()
		rec := b.serve(h, member, "createPrivateAddonUpload", http.MethodPost, "/api/v1/addon-scan-uploads", nil, payload, headers)
		if rec.Code != want {
			t.Fatalf("grant status %d want %d: %s", rec.Code, want, rec.Body.String())
		}
		return rec.Body.Bytes()
	}
	call(body, 403)
	b.seed(func() {
		b.exec(`INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled,version,updated_at) VALUES($1,$2,$3,'staging','extended',1,true,1,clock_timestamp()) ON CONFLICT(organization_id,workspace_id,environment_id) DO UPDATE SET environment_class='staging',collection_mode='extended'`, b.o, b.w, b.e)
	})
	call(body, 403) // A controls row cannot enable private source in a production Environment.
	b.seed(func() {
		b.exec(`UPDATE public.zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3)`, b.o, b.w, b.e)
	})
	retainedBody := strings.Replace(body, "memory_only", "encrypted_24h", 1)
	call(retainedBody, 503)
	t.Setenv("ZASP_PRIVATE_ADDON_RETAINED_SCOPE", scope)
	originalKey := headers["Idempotency-Key"]
	headers["Idempotency-Key"] = "private-retain-" + b.id()
	retained := call(retainedBody, 200)
	var expires struct {
		Until time.Time `json:"retain_until"`
		TTL   time.Time `json:"expires_at"`
		Mode  string    `json:"retention"`
	}
	if json.Unmarshal(retained, &expires) != nil || expires.Mode != "encrypted_24h" || !expires.Until.Equal(expires.TTL.Add(24*time.Hour-5*time.Minute)) || !bytes.Equal(retained, call(retainedBody, 200)) {
		t.Fatal("retained grant missing stable deletion deadline")
	}
	call(body, 409)
	headers["Idempotency-Key"] = originalKey
	reply := call(body, 200)
	call(retainedBody, 409)
	if !bytes.Equal(reply, call(body, 200)) {
		t.Fatal("grant retry changed")
	}
	var g struct {
		ID    string `json:"id"`
		Grant string `json:"upload_grant"`
		Key   string `json:"verification_key"`
		URL   string `json:"upload_url"`
	}
	if json.Unmarshal(reply, &g) != nil || g.URL != "https://private.example.invalid/v1/uploads/"+g.ID {
		t.Fatal("invalid upload destination")
	}
	data, sig, ok := strings.Cut(g.Grant, ".")
	raw, e1 := base64.RawURLEncoding.DecodeString(data)
	signature, e2 := base64.RawURLEncoding.DecodeString(sig)
	key, e3 := base64.RawURLEncoding.DecodeString(g.Key)
	if !ok || e1 != nil || e2 != nil || e3 != nil || !ed25519.Verify(key, append([]byte("zasp-private-addon-upload.v1\x00"), raw...), signature) {
		t.Fatal("grant signature failed")
	}
	var payload privateArchiveGrant
	if json.Unmarshal(raw, &payload) != nil || payload.Scope != scope || payload.Size != 998 || payload.SHA256 != digest || payload.ID != g.ID || payload.Actor != member.identity.PrincipalID.String() {
		t.Fatal("grant binding incomplete")
	}
	call(strings.Replace(body, "998", "999", 1), 409)
	issue, _ := installedWorkloadTokenIssuer(t, b, repo, member)
	worker := issue("Private add-on worker", `["submit_addon_scans"]`)
	other := issue("Independent findings submission", `["submit_addon_scans"]`)
	t.Setenv("ZASP_PRIVATE_ADDON_RESULT_CREDENTIAL", worker.binding.ID)
	headers["Idempotency-Key"] = "private-registry-" + b.id()
	if json.Unmarshal(call(body, 200), &g) != nil {
		t.Fatal("invalid registered grant")
	}
	data, _, _ = strings.Cut(g.Grant, ".")
	raw, _ = base64.RawURLEncoding.DecodeString(data)
	if json.Unmarshal(raw, &payload) != nil || !payload.Registry {
		t.Fatal("registered mode missing from signed grant")
	}
	manifest := `"sha256:` + strings.Repeat("c", 64) + `"`
	report := strings.Replace(addonTestReport(b.e, manifest), `"origin":"local"`, `"origin":"private_worker","private_upload":{"id":"`+g.ID+`","archive_digest":"`+digest+`","archive_bytes":998}`, 1)
	surface := &discoveryWorkflowSurface{addons: &addonReviewHandler{database: b.product, newProductID: func() (string, error) { return b.id(), nil }}}
	keyValue := "private-upload-" + g.ID
	post := func(caller installedPrincipal, key, input string, want int) map[string]any {
		t.Helper()
		res := b.serve(surface, caller, "submitAddonScan", http.MethodPost, "/api/v1/addon-scans", nil, input, map[string]string{"Idempotency-Key": key})
		if res.Code != want {
			t.Fatalf("registered submit got %d want %d: %s", res.Code, want, res.Body.String())
		}
		var obj map[string]any
		if json.Unmarshal(res.Body.Bytes(), &obj) != nil {
			t.Fatal("invalid submission response")
		}
		return obj
	}
	post(other, keyValue, report, 403)
	post(worker, "private-upload-"+b.id(), report, 403)
	post(worker, keyValue, strings.Replace(report, digest, "sha256:"+strings.Repeat("e", 64), 1), 403)
	post(worker, keyValue, strings.Replace(report, "998", "997", 1), 403)
	post(worker, keyValue, strings.Replace(report, "private_worker", "local", 1), 400)
	v := post(worker, keyValue, report, 200)
	if post(worker, keyValue, report, 200)["scan_id"] != v["scan_id"] {
		t.Fatal("lost response replay created a duplicate")
	}
	version, _ := v["version_id"].(string)
	if !validProductID(version) || v["review_path"] != "/inventory/tools?addon="+version {
		t.Fatalf("missing version receipt: %v", v)
	}
	detail := b.serve(surface, member, "getAddonVersion", http.MethodGet, "/api/v1/addon-versions/"+version, map[string]string{"id": version}, "", nil)
	var reviewed map[string]any
	if detail.Code != 200 || json.Unmarshal(detail.Body.Bytes(), &reviewed) != nil || reviewed["origin"] != "private_worker" || reviewed["provenance"] != "reported" || reviewed["review_state"] != "pending" {
		t.Fatalf("version status %d: %s", detail.Code, detail.Body.String())
	}
	t.Setenv("ZASP_PRIVATE_ADDON_WORKER_SCOPE", scope+"x")
	call(body, 503)
}
