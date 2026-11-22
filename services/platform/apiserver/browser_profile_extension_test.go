package apiserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testBrowserExtensionSync(t *testing.T, b *installedBaseline, repo *PostgresRepository, data http.Handler, admin, profile installedPrincipal, secret string) {
	t.Helper()
	// Only the test-side key handoff uses a helper route. Admin registration,
	// the profile POST, bearer authentication and its readback use their real handlers.
	path := "/api/v1/browser-profiles/" + profile.binding.ID
	params := map[string]string{"id": profile.binding.ID}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/fixture/approve-public-key" {
			var body struct {
				Key string `json:"key"`
			}
			if json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&body) != nil {
				http.Error(w, "invalid", 400)
				return
			}
			registration, _ := json.Marshal(map[string]any{"public_key": body.Key, "origins": []string{"https://claude.ai"}})
			rec := b.serve(data, admin, "registerBrowserProfile", "PUT", path, params, string(registration), nil)
			w.WriteHeader(rec.Code)
			return
		}
		if r.URL.Path != path+"/observations" {
			http.NotFound(w, r)
			return
		}
		i, err := repo.Authenticate(r.Context(), Credential{Kind: CredentialBearerToken, Value: strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")})
		if err != nil {
			http.Error(w, "unauthenticated", 401)
			return
		}
		ctx, err := b.checked(installedPrincipal{identity: i, binding: i.credentialBinding}, RoutedOperation{OperationID: "recordBrowserOriginDays", PathParameters: params})
		if err != nil {
			http.Error(w, "denied", 403)
			return
		}
		data.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer server.Close()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("Node.js 22 is required for the managed browser integration test")
	}
	script, err := filepath.Abs("../../../extensions/browser-guard/test/installed-profile.mjs")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(b.ctx, node, script)
	cmd.Env = append(os.Environ(), "BROWSER_TEST_ORIGIN="+server.URL, "BROWSER_TEST_ID="+profile.binding.ID, "BROWSER_TEST_ENV="+b.e, "BROWSER_TEST_TOKEN="+secret)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("extension origin-day report failed: %v %s", err, out)
	}
	read := b.serve(data, admin, "getBrowserProfile", "GET", path, params, "", nil)
	if read.Code != 200 || !strings.Contains(read.Body.String(), `"state":"reporting"`) || !strings.Contains(read.Body.String(), `"origin":"https://claude.ai"`) {
		t.Fatal("missing actual profile readback", read.Code, read.Body)
	}
}
