package apiserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManagedBrowserProfileOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issue, secrets := installedWorkloadTokenIssuer(t, b, repository, admin)
	member := issue("Managed Chrome", `["report_browser_usage"]`)
	neighbour := issue("Managed Edge", `["report_browser_usage"]`)
	if _, err := b.checked(member, RoutedOperation{OperationID: "getBrowserProfile", PathParameters: map[string]string{"id": member.binding.ID}}); err == nil {
		t.Fatal("profile token read admin view")
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		serveBrowserProfile(b.product, w, r, op)
	})
	id := member.binding.ID
	params := map[string]string{"id": id}
	path := "/api/v1/browser-profiles/" + id
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPublic := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	register, _ := json.Marshal(map[string]any{"public_key": base64.StdEncoding.EncodeToString(signPublic), "origins": []string{"https://claude.ai"}})
	put := func() *httptest.ResponseRecorder {
		return b.serve(h, admin, "registerBrowserProfile", "PUT", path, params, string(register), nil)
	}
	get := func() *httptest.ResponseRecorder {
		return b.serve(h, admin, "getBrowserProfile", "GET", path, params, "", nil)
	}
	if r := put(); r.Code != 200 || !strings.Contains(r.Body.String(), "awaiting_profile") {
		t.Fatal("register", r.Code, r.Body)
	}
	makeReport := func(origin string) browserReport {
		var n [16]byte
		if _, err := rand.Read(n[:]); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		report := browserReport{IssuedAt: now.Unix(), Nonce: hex.EncodeToString(n[:]), Days: []browserDay{{origin, now.Format("2006-01-02")}}, Signature: make([]byte, 64)}
		digest, ok := report.signingDigest(id, now)
		if !ok {
			t.Fatal("fixture malformed")
		}
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			t.Fatal(err)
		}
		r.FillBytes(report.Signature[:32])
		s.FillBytes(report.Signature[32:])
		return report
	}
	send := func(member installedPrincipal, report browserReport) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(report)
		return b.serve(h, member, "recordBrowserOriginDays", "POST", path+"/observations", params, string(raw), nil)
	}
	good := makeReport("https://claude.ai")
	if r := send(neighbour, good); r.Code != 403 {
		t.Fatal("cross-profile", r.Code, r.Body)
	}
	if r := send(member, makeReport("https://chatgpt.com")); r.Code != 403 {
		t.Fatal("off-list", r.Code, r.Body)
	}
	testBrowserExtensionSync(t, b, repository, h, admin, neighbour, secrets["Managed Edge"])
	b.exec(`UPDATE zasp_product_api_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, neighbour.binding.ID)
	expired := b.serve(h, admin, "getBrowserProfile", "GET", "/api/v1/browser-profiles/"+neighbour.binding.ID, map[string]string{"id": neighbour.binding.ID}, "", nil)
	if expired.Code != 200 || !strings.Contains(expired.Body.String(), `"state":"expired"`) {
		t.Fatal("expired profile", expired.Code, expired.Body)
	}
	tampered := good
	tampered.Signature = append([]byte{}, good.Signature...)
	tampered.Signature[0] ^= 1
	if r := send(member, tampered); r.Code != 403 {
		t.Fatal("signature", r.Code, r.Body)
	}
	for i := 0; i < 2; i++ {
		if r := send(member, good); r.Code != 200 {
			t.Fatal("sync", r.Code, r.Body)
		}
	}
	var view struct {
		State   string       `json:"state"`
		LastDay string       `json:"last_observation"`
		Days    []browserDay `json:"observations"`
	}
	if r := get(); r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &view) != nil || view.State != "reporting" || view.LastDay != good.Days[0].Day || len(view.Days) != 1 || view.Days[0] != good.Days[0] {
		t.Fatal("profile status", r.Code, r.Body)
	}
	b.exec(`UPDATE zasp_browser_profiles SET last_sync=clock_timestamp()-interval '3 hours' WHERE credential_id=$1`, id)
	if r := get(); r.Code != 200 || !strings.Contains(r.Body.String(), "stale") {
		t.Fatal("stale", r.Code, r.Body)
	}
	if r := b.serve(h, admin, "retireBrowserProfile", "DELETE", path, params, "", nil); r.Code != 200 || !strings.Contains(r.Body.String(), "revoked") {
		t.Fatal("retirement", r.Code, r.Body)
	}
	if r := send(member, good); r.Code != 403 {
		t.Fatal("revoked", r.Code, r.Body)
	}
}
