package cliauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/browserlink"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testEnvironment = "pid_10000000-0000-4000-8000-000000000001"
const testRequest = "pid_20000000-0000-4000-8000-000000000001"

func TestHTTPSBrowserPairedExchange(t *testing.T) {
	for _, result := range []string{"ok", "wrong_environment", "bad_scope", "expired_token", "bad_type", "credential_store_locked"} {
		t.Run(result, func(t *testing.T) {
			var challenge string
			polls := 0
			token := "zasp_cli_" + strings.Repeat("A", 43)
			expiry := time.Now().Add(5 * time.Minute).Truncate(time.Second)
			proof := fmt.Sprintf("%d.%s", expiry.Unix(), strings.Repeat("X", 43))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("unexpected credential or method")
				}
				var body map[string]string
				if json.NewDecoder(r.Body).Decode(&body) != nil || body["client_id"] != "zaspctl" || body["environment_id"] != testEnvironment {
					t.Error("invalid request")
				}
				switch r.URL.Path {
				case "/api/v1/cli/auth/start":
					challenge = body["code_challenge"]
					if body["code_challenge_method"] != "S256" || len(challenge) != 43 || body["code_verifier"] != "" {
						t.Error("invalid start")
					}
					json.NewEncoder(w).Encode(map[string]any{"request_id": testRequest, "request_proof": proof, "comparison_code": "abc123de", "expires_at": expiry})
				case "/api/v1/cli/auth/exchange":
					sum := sha256.Sum256([]byte(body["code_verifier"]))
					if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || body["request_id"] != testRequest {
						t.Error("verifier did not match")
					}
					polls++
					if polls == 1 {
						w.WriteHeader(409)
						return
					}
					g := grant{Token: token, Type: "Bearer", Scope: "submit_addon_scans", Environment: testEnvironment, Expires: time.Now().Add(15 * time.Minute)}
					switch result {
					case "wrong_environment":
						g.Environment = testRequest
					case "bad_scope":
						g.Scope = "manage_api_tokens"
					case "expired_token":
						g.Expires = time.Now().Add(-time.Minute)
					case "bad_type":
						g.Type = ""
					}
					json.NewEncoder(w).Encode(g)
				default:
					t.Error("unexpected route")
				}
			}))
			defer server.Close()
			presented, saved := false, false
			flow := loginFlow{client: server.Client(), wait: time.Millisecond, present: func(link, code string) {
				presented = true
				page, err := url.Parse(link)
				if err != nil || page.Path != "/cli/authorize" || page.RawQuery != "" || code != "abc123de" || strings.Contains(link, code) || strings.Contains(link, token) {
					t.Error("unexpected browser handoff")
				}
				fields, err := url.ParseQuery(page.Fragment)
				if err != nil || len(fields) != 4 || fields.Get("code_challenge") != challenge || fields.Get("request_proof") != proof || fields.Get("request_id") != testRequest {
					t.Error("invalid challenge binding")
				}
			}, save: func(host, env string, data []byte) error {
				saved = true
				var v grant
				if json.Unmarshal(data, &v) != nil || v.Token != token || host != server.URL || env != testEnvironment {
					t.Error("bad keychain write")
				}
				if result == "credential_store_locked" {
					return errStore
				}
				return nil
			}}
			err := flow.execute(context.Background(), server.URL, testEnvironment)
			if !presented || polls != 2 || (err == nil) != (result == "ok") || saved != (result == "ok" || result == "credential_store_locked") {
				t.Fatalf("err=%v presented=%v saved=%v polls=%d", err, presented, saved, polls)
			}
		})
	}
}
func TestCredentialOrigin(t *testing.T) {
	canonical, ok := browserlink.Origin("https://EXAMPLE.test:443/")
	if !ok || canonical != "https://example.test" {
		t.Fatal(canonical)
	}
	for _, s := range []string{"http://example.test", "https://user@example.test", "https://example.test/extra", "https://example.test?token=x", "https://example.test:99999", "https://example.test/#token"} {
		if _, ok := browserlink.Origin(s); ok {
			t.Fatalf("accepted invalid origin %s", s)
		}
	}
}
