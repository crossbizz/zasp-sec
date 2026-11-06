package preflight

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const stytchOrganizationFixture = "organization-test-11111111-1111-4111-8111-111111111111"
const stytchMemberFixture = "member-test-22222222-2222-4222-8222-222222222222"
const stytchSessionFixture = "member-session-test-33333333-3333-4333-8333-333333333333"

type stytchProbeTransport struct {
	mode      string
	calls     int
	forbidden bool
}

func (tr *stytchProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr.calls++
	if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != "test.stytch.com" || r.Body != nil {
		tr.forbidden = true
	}
	project, secret, ok := r.BasicAuth()
	if !ok || !strings.HasPrefix(project, "project-test-") || secret != "fixture-stytch-secret" {
		tr.forbidden = true
	}
	status := 200
	var value any
	switch r.URL.Path {
	case "/v1/b2b/organizations/" + stytchOrganizationFixture:
		if r.URL.RawQuery != "" {
			tr.forbidden = true
		}
		value = map[string]any{"status_code": 200, "organization": map[string]any{"organization_id": stytchOrganizationFixture, "unrelated_optional": nil}}
	case "/v1/b2b/sessions":
		q := r.URL.Query()
		if len(q) != 2 || q.Get("organization_id") != stytchOrganizationFixture || q.Get("member_id") != stytchMemberFixture {
			tr.forbidden = true
		}
		now := time.Now().UTC()
		session := map[string]any{"member_session_id": stytchSessionFixture, "member_id": stytchMemberFixture, "organization_id": stytchOrganizationFixture, "started_at": now.Add(-time.Hour).Format(time.RFC3339), "last_accessed_at": now.Add(-time.Minute).Format(time.RFC3339), "expires_at": now.Add(time.Hour).Format(time.RFC3339), "custom_claims": nil}
		switch tr.mode {
		case "wrong-member":
			session["member_id"] = "member-test-44444444-4444-4444-8444-444444444444"
		case "wrong-org":
			session["organization_id"] = "organization-test-44444444-4444-4444-8444-444444444444"
		case "alias-member":
			session["MEMBER_ID"] = session["member_id"]
			delete(session, "member_id")
		case "mixed-case-duplicate":
			session["MEMBER_ID"] = session["member_id"]
		case "expired":
			session["expires_at"] = now.Add(-time.Second).Format(time.RFC3339)
		case "replacement":
			session["member_session_id"] = "member-session-test-44444444-4444-4444-8444-444444444444"
		}
		list := []any{session}
		if tr.mode == "revoked" {
			list = []any{}
		}
		if tr.mode == "duplicate-session" {
			list = append(list, session)
		}
		value = map[string]any{"status_code": 200, "member_sessions": list, "unrelated_optional": nil}
	default:
		tr.forbidden = true
		status = 404
		value = map[string]any{"status_code": 404}
	}

	if tr.mode == "alias-status" {
		object := value.(map[string]any)
		object["STATUS_CODE"] = object["status_code"]
		delete(object, "status_code")
	}
	if tr.mode == "alias-organization" && strings.HasPrefix(r.URL.Path, "/v1/b2b/organizations/") {
		organization := value.(map[string]any)["organization"].(map[string]any)
		organization["Organization_ID"] = organization["organization_id"]
		delete(organization, "organization_id")
	}
	body, _ := json.Marshal(value)
	if tr.mode == "denied" {
		status = 403
		body = []byte(`{"error_message":"NEVER_REFLECT_PROVIDER_TEXT"}`)
	}
	if tr.mode == "malformed" {
		body = []byte(`{"status_code":200,"status_code":200}`)
	}
	if tr.mode == "oversize" {
		body = []byte(strings.Repeat("x", 65537))
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
}
func stytchProbeConfig(t *testing.T) *StytchConfig {
	t.Helper()
	file := filepath.Join(t.TempDir(), "identity.json")
	if os.WriteFile(file, []byte(`{"project_id":"project-test-55555555-5555-4555-8555-555555555555","secret":"fixture-stytch-secret"}`), 0600) != nil {
		t.Fatal("controlled private identity source unavailable")
	}
	return &StytchConfig{Origin: "https://test.stytch.com", CredentialFile: file, OrganizationID: stytchOrganizationFixture, MemberID: stytchMemberFixture, MemberSessionID: stytchSessionFixture}
}
func TestNonrenewingStytchObservations(t *testing.T) {
	for _, mode := range []string{"observed-null-fields", "wrong-member", "wrong-org", "expired", "revoked", "replacement", "duplicate-session", "denied", "malformed", "oversize", "alias-status", "alias-organization", "alias-member", "mixed-case-duplicate"} {
		t.Run(mode, func(t *testing.T) {
			config := stytchProbeConfig(t)
			tr := &stytchProbeTransport{mode: mode}
			r := &Runner{config: sdkContractConfig(t), http: &http.Client{Transport: tr}}
			report := initialReport(r.config, "installed")
			r.observeStytch(context.Background(), &report, config)
			if tr.calls == 0 || tr.forbidden {
				t.Fatal("observer skipped provider boundary or used unexpected authority/route/renewal")
			}
			o := report.Checks[6].Observations
			if mode == "observed-null-fields" {
				if tr.calls != 2 || o[0].Status != "pass" || o[1].Status != "pass" || o[1].Code != "observed_selected_provider_session" {
					t.Fatal("exact existing provider session absent or null optional fields rejected")
				}
			} else if o[1].Status == "pass" || len(o[0].Failures)+len(o[1].Failures) == 0 {
				t.Fatal("bad provider fact accepted or precise failure unavailable")
			}
			body, _ := json.Marshal(report)
			if strings.Contains(string(body), "fixture-stytch-secret") || strings.Contains(string(body), "NEVER_REFLECT_PROVIDER_TEXT") || strings.Contains(string(body), stytchSessionFixture) {
				t.Fatal("provider secret, text or selected identity leaked")
			}
			if report.Ready || report.ProductionEndToEndVerified {
				t.Fatal("read observation became production or tenant enrollment proof")
			}
		})
	}
}
