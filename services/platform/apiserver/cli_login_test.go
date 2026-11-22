package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testCLIPair(octet byte) (string, string) {
	verifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{octet}, 32))
	hash := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(hash[:])
}

func TestCLILoginProofBindsEnvironmentRequestAndTime(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	now := time.Now().UTC()
	expiry := strconv.FormatInt(now.Unix()+300, 10)
	_, challenge := testCLIPair(2)
	id, _ := newWorkflowProductID()
	env, _ := newWorkflowProductID()
	in := cliApproval{cliClientID, env, id, challenge, cliStartProof(key, id, env, challenge, expiry), cliComparison(key, id, env, challenge, expiry)}
	if _, ok := in.verify(key, now); !ok {
		t.Fatal("valid approval refused")
	}
	for _, change := range []func(*cliApproval){func(a *cliApproval) { a.Code = "xxxxxxxx" }, func(a *cliApproval) { a.ID, _ = newWorkflowProductID() }, func(a *cliApproval) { a.Environment, _ = newWorkflowProductID() }, func(a *cliApproval) { _, a.Challenge = testCLIPair(7) }, func(a *cliApproval) { a.Client = "other" }} {
		candidate := in
		change(&candidate)
		if _, ok := candidate.verify(key, now); ok {
			t.Fatal("modified approval accepted")
		}
	}
	if _, ok := in.verify(key, now.Add(5*time.Minute)); ok {
		t.Fatal("expired approval accepted")
	}
	if _, ok := in.verify(bytes.Repeat([]byte{0x77}, 32), now); ok {
		t.Fatal("foreign deployment key accepted")
	}
}

func TestCLILoginOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	developer := b.member("developer_owner", "investigate_sessions", "run_tests", "view")
	viewer := b.member("read_only_viewer", "view")
	browser := developer
	// Installed fixtures substitute the OpenFGA decision for these real roles.
	b.refused[developer.identity.PrincipalID.String()+" manage_api_tokens"] = true
	b.refused[viewer.identity.PrincipalID.String()+" run_tests"] = true
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	installedIdentityVerifiers(b)
	h := &identityHTTPHandler{repository: repo, tokenRevealKey: bytes.Repeat([]byte{0xa3}, 32), now: time.Now}
	paths := map[string]string{"startCLILogin": "/api/v1/cli/auth/start", "approveCLILogin": "/api/v1/cli/auth/approve", "exchangeCLILogin": "/api/v1/cli/auth/exchange"}
	router, err := NewRouter([]Operation{
		{Method: "POST", Pattern: paths["startCLILogin"], OperationID: "startCLILogin", Handler: h},
		{Method: "POST", Pattern: paths["approveCLILogin"], OperationID: "approveCLILogin", Permission: "run_tests", Security: []CredentialKind{CredentialBrowserSession}, RequireFreshAuth: true, RequireCSRF: true, Handler: h},
		{Method: "POST", Pattern: paths["exchangeCLILogin"], OperationID: "exchangeCLILogin", Handler: h},
	})
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = b.authorizer
	server, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://app.zasp.test", MaximumBodyBytes: 16 * 1024, Authenticate: repo.Authenticate, GenerateCorrelationID: func() string { return b.id() }}, router)
	if err != nil {
		t.Fatal(err)
	}
	call := func(op string, body any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, paths[op], bytes.NewReader(encoded)).WithContext(b.ctx)
		req.Header.Set("Content-Type", "application/json")
		if op == "approveCLILogin" {
			req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "session-secret-" + browser.identity.PrincipalID.String()})
			req.Header.Set("Origin", "https://app.zasp.test")
			req.Header.Set("X-CSRF-Token", browser.identity.CSRFToken)
			req.Header.Set(expectedScopeHeader, expectedScopeValue(browser.identity.Scope))
		}
		resp := httptest.NewRecorder()
		server.ServeHTTP(resp, req)
		if resp.Code == 200 && resp.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("no-store missing")
		}
		return resp
	}
	verifier, challenge := testCLIPair(42)
	start := call("startCLILogin", cliStart{cliClientID, b.e, "S256", challenge})
	var first struct {
		ID    string `json:"request_id"`
		Proof string `json:"request_proof"`
		Code  string `json:"comparison_code"`
	}
	if start.Code != 200 || json.Unmarshal(start.Body.Bytes(), &first) != nil || !validProductID(first.ID) {
		t.Fatalf("start code %d", start.Code)
	}
	poll := cliExchange{cliClientID, b.e, first.ID, verifier}
	if r := call("exchangeCLILogin", poll); r.Code != 409 {
		t.Fatalf("pending exchange %d", r.Code)
	}
	approval := cliApproval{cliClientID, b.e, first.ID, challenge, first.Proof, first.Code}
	if _, err := b.checked(developer, RoutedOperation{OperationID: "createAPIToken", PathParameters: map[string]string{}}); err == nil {
		t.Fatal("developer can manage general API credentials")
	}
	browser = viewer
	if got := call("approveCLILogin", approval); got.Code != http.StatusForbidden {
		t.Fatalf("read-only viewer consent %d %s", got.Code, got.Body)
	}
	browser = developer
	invalid := approval
	invalid.Environment = b.id()
	if r := call("approveCLILogin", invalid); r.Code == 200 {
		t.Fatal("accepted foreign Environment")
	}
	for i := 0; i < 2; i++ {
		r := call("approveCLILogin", approval)
		if r.Code != 200 {
			t.Fatalf("approve returned %d %s", r.Code, r.Body.String())
		}
		if strings.Contains(r.Body.String(), "zasp_cli_") {
			t.Fatal("browser received token")
		}
	}
	incorrect := poll
	incorrect.Verifier, _ = testCLIPair(21)
	if r := call("exchangeCLILogin", incorrect); r.Code != 409 {
		t.Fatalf("bad verifier status %d", r.Code)
	}
	out := call("exchangeCLILogin", poll)
	var result struct {
		Access      string    `json:"access_token"`
		Scope       string    `json:"scope"`
		Environment string    `json:"environment_id"`
		Expires     time.Time `json:"expires_at"`
	}
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || !strings.HasPrefix(result.Access, "zasp_cli_") || result.Scope != permissionSubmitAddonScans || result.Environment != b.e || !result.Expires.After(time.Now()) || time.Until(result.Expires) > 15*time.Minute {
		t.Fatalf("exchange status %d", out.Code)
	}
	if r := call("exchangeCLILogin", poll); r.Code != 409 {
		t.Fatalf("replayed exchange %d", r.Code)
	}
	auth, err := repo.Authenticate(b.ctx, Credential{Kind: CredentialBearerToken, Value: result.Access})
	if err != nil || auth.Scope.EnvironmentID().String() != b.e || len(auth.credentialBinding.PATCeiling) != 1 || auth.credentialBinding.PATCeiling[0] != permissionSubmitAddonScans {
		t.Fatalf("result not a usable isolated credential: %v", err)
	}
	surface := &discoveryWorkflowSurface{addons: &addonReviewHandler{database: b.product, newProductID: newWorkflowProductID}}
	resolve := b.serve(surface, installedPrincipal{auth, auth.credentialBinding}, "submitAddonScan", http.MethodPost, "/api/v1/addon-scans", nil, addonTestReport(b.e, `"sha256:`+strings.Repeat("b", 64)+`"`), map[string]string{"Idempotency-Key": "cli-report-" + b.id()})
	if resolve.Code != http.StatusOK {
		t.Fatalf("issued CLI credential cannot submit findings: %d %s", resolve.Code, resolve.Body.String())
	}
	for _, forbidden := range []string{"getAPITokenPolicy", "runTest", "reviewAddonVersion", "listComplianceEvidence", "createPolicy"} {
		if _, err = b.authorizer.Authorize(b.ctx, auth, auth.credentialBinding, RoutedOperation{OperationID: forbidden, PathParameters: map[string]string{"id": b.id()}}); err == nil {
			t.Fatalf("findings-only token allowed %s", forbidden)
		}
	}
	local := addonTestReport(b.e, `"sha256:`+strings.Repeat("a", 64)+`"`)
	submit := func(raw string) *httptest.ResponseRecorder {
		return b.serve(surface, installedPrincipal{auth, auth.credentialBinding}, "submitAddonScan", "POST", "/api/v1/addon-scans", nil, raw, map[string]string{"Idempotency-Key": "cli-after-" + b.id()})
	}
	if r := submit(strings.Replace(local, `"local"`, `"ci"`, 1)); r.Code != 403 {
		t.Fatal("findings-only token claimed CI source", r.Code, r.Body)
	}
	// Approve one more short-lived request, then remove the workload-testing
	// grant before exchange. An existing bearer must also stop submitting.
	second := call("startCLILogin", cliStart{cliClientID, b.e, "S256", challenge})
	if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &first) != nil {
		t.Fatal(second.Code, second.Body)
	}
	approval.ID, approval.Proof, approval.Code = first.ID, first.Proof, first.Code
	if r := call("approveCLILogin", approval); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	b.seed(func() {
		b.exec(`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, b.o, developer.identity.PrincipalID.String())
	})
	poll.ID = first.ID
	if r := call("exchangeCLILogin", poll); r.Code != 409 {
		t.Fatal("downgraded user redeemed", r.Code, r.Body)
	}
	if r := submit(local); r.Code != 403 {
		t.Fatal("downgraded user submitted", r.Code, r.Body)
	}

}

func TestCLILoginNativeEntryRejectsAmbientCredentials(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := newTestMiddleware(t, next, func(context.Context, Credential) (RequestIdentity, error) {
		t.Fatal("unexpected ambient authentication")
		return RequestIdentity{}, nil
	})
	for _, op := range []string{"start", "exchange"} {
		for _, tc := range []struct {
			name, value string
			want        int
		}{
			{"", "", 204}, {"Origin", "https://app.zasp.test", 403}, {"Cookie", "other=empty", 403}, {"Authorization", "Bearer placeholder", 403},
		} {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/cli/auth/"+op, strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			if tc.name != "" {
				r.Header.Set(tc.name, tc.value)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != tc.want {
				t.Fatalf("%s %s %d", op, tc.name, rec.Code)
			}
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/cli/auth/approve", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated approval returned %d", rec.Code)
	}
}
