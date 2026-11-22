package apiserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAddonOriginOnInstalledBaselinePostgres(t *testing.T) {
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
	ci := issue("CI origin", `["submit_addon_scans"]`)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHash := sha256.Sum256(public)
	kid := hex.EncodeToString(keyHash[:])
	operator := b.login("zasp_operator")
	slug := "sample-org/private-skills"
	rev := strings.Repeat("d", 40)
	register := func(retire bool) {
		t.Helper()
		var id string
		if err := operator.QueryRow(b.ctx, `SELECT zasp_authorization80.register_addon_ci_key($1,$2,$3,$4,$5,$6,$7)`, b.o, b.w, b.e, ci.binding.ID, slug, []byte(public), retire).Scan(&id); err != nil || id != kid {
			t.Fatalf("register or revoke signer: %v", err)
		}
	}
	register(false)
	surface := &discoveryWorkflowSurface{addons: &addonReviewHandler{database: b.product, newProductID: func() (string, error) { return b.id(), nil }}}
	digest := "sha256:" + strings.Repeat("b", 64)
	submit := func(origin, d string) map[string]any {
		t.Helper()
		rec := b.serve(surface, ci, "submitAddonScan", "POST", "/api/v1/addon-scans", nil, strings.Replace(addonTestReport(b.e, `"`+d+`"`), `"local"`, `"`+origin+`"`, 1), map[string]string{"Idempotency-Key": "origin-fixture-" + b.id()})
		var result map[string]any
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil {
			t.Fatalf("submission: %d %s", rec.Code, rec.Body.String())
		}
		return result
	}
	cloud := submit("ci", digest)
	local := submit("local", digest)
	edited := submit("local", "sha256:"+strings.Repeat("c", 64))
	scan := cloud["scan_id"].(string)
	get := func(id any) ciOriginView {
		t.Helper()
		rid := id.(string)
		res := b.serve(surface, admin, "getAddonCIOrigin", "GET", "/api/v1/addon-versions/"+rid+"/ci-origin", map[string]string{"id": rid}, "", nil)
		var view ciOriginView
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &view) != nil {
			t.Fatalf("origin %d %s", res.Code, res.Body.String())
		}
		return view
	}
	if v := get(cloud["version_id"]); v.Status != "unknown" {
		t.Fatal("unsigned CI report gained provenance")
	}
	fields := []string{"zasp-ci-manifest-attestation.v1", b.e, ci.binding.ID, scan, kid, slug, rev, digest, "zasp-static.v1", "script.network_access=1"}
	sig := ed25519.Sign(private, []byte(strings.Join(fields, "\n")+"\n"))
	attest := func(commit string, signature []byte, want int) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"key_id": kid, "repository": slug, "commit": commit, "signature": base64.RawURLEncoding.EncodeToString(signature)})
		res := b.serve(surface, ci, "attestAddonScan", "POST", "/api/v1/addon-scans/"+scan+"/ci-attestation", map[string]string{"id": scan}, string(body), nil)
		if res.Code != want {
			t.Fatalf("signature %d want %d, %s", res.Code, want, res.Body.String())
		}
	}
	attest(strings.Repeat("e", 40), sig, 403)
	attest(rev, sig, 200)
	attest(rev, sig, 200)
	if v := get(cloud["version_id"]); v.Status != "verified" || v.Match == nil || *v.Match != "direct" || v.Repository == nil || *v.Repository != slug || v.Commit == nil || *v.Commit != rev {
		t.Fatalf("direct %+v", v)
	}
	if v := get(local["version_id"]); v.Status != "verified" || v.Match == nil || *v.Match != "same_manifest" {
		t.Fatalf("matching bytes %+v", v)
	}
	if v := get(edited["version_id"]); v.Status != "unknown" {
		t.Fatal("local edit borrowed origin")
	}
	// A separate real tenant cannot load the pinned version or discover matching CI evidence.
	other := startInstalledV2Baseline(t)
	peer := other.member("security_engineer", "view", "investigate_sessions", "manage_findings", "manage_workflows", "run_tests")
	if err := other.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	foreignSurface := &discoveryWorkflowSurface{addons: &addonReviewHandler{database: other.product}}
	for _, op := range []string{"getAddonVersion", "getAddonCIOrigin", "listAddonVersionInstallations"} {
		id := cloud["version_id"].(string)
		res := other.serve(foreignSurface, peer, op, http.MethodGet, "/api/v1/addon-versions/"+id, map[string]string{"id": id}, "", nil)
		if res.Code != 404 {
			t.Fatalf("other tenant %s returned %d %s", op, res.Code, res.Body.String())
		}
	}
	register(true)
	if v := get(local["version_id"]); v.Status != "unknown" {
		t.Fatal("retired signer still trusted")
	}
	attest(rev, sig, 404)
}
