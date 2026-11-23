package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/providerhooks"
)

func TestClaudePublicActivationAndSecretFile(t *testing.T) {
	const id = "pid_11111111-1111-4111-8111-111111111111"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	disabled, err := mountClaudeProvider(next, next, "", true)
	if err != nil {
		t.Fatal(err)
	}
	call := func(h http.Handler, path string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer untrusted-caller-token")
		h.ServeHTTP(w, r)
		return w.Code
	}
	if call(disabled, providerhooks.ClaudePath+id) != 404 || call(disabled, "/api/v1/runtime/action-decisions") != 202 {
		t.Fatal("disabled hook did not isolate its route")
	}
	cfg := claudeProviderFile{Integration: id, Tenant: "enterprise-tenant", Organization: id, Workspace: id, Environment: id, Credential: id, SigningSecret: "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32)), ReferenceKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32)), Token: strings.Repeat("x", 64)}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "provider.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	enabled, err := mountClaudeProvider(next, next, path, true)
	if err != nil {
		t.Fatal(err)
	}
	if call(enabled, providerhooks.ClaudePath+id) != 401 || call(enabled, providerhooks.ClaudePath+"unknown") != 404 || call(enabled, "/api/v1/findings") != 202 {
		t.Fatal("provider route did not require signed identity")
	}
	if _, err = mountClaudeProvider(next, next, path, false); err == nil {
		t.Fatal("accepted legacy authorization")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = mountClaudeProvider(next, next, path, true); err == nil {
		t.Fatal("accepted world-readable secret")
	}
}
