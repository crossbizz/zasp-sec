//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

const auditBrowserProviderReaderRole = "arn:aws:iam::123456789012:role/zasp-owned-audit-browser-reader"

func auditBrowserReaderCredentials() aws.Credentials {
	return aws.Credentials{AccessKeyID: "ASIABROWSERREADER", SecretAccessKey: "owned-browser-reader-secret-not-real", SessionToken: "owned-browser-reader-session"}
}

func auditBrowserReaderSTS(next http.Handler) (http.Handler, *atomic.Int64) {
	count := new(atomic.Int64)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "sts.us-east-1.amazonaws.com" {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.Method != "POST" || r.URL.Path != "/" || r.URL.RawQuery != "" || r.ParseForm() != nil {
			http.Error(w, "owned STS framing refused", 400)
			return
		}
		role, session := r.Form.Get("RoleArn"), r.Form.Get("RoleSessionName")
		if role != auditBrowserProviderReaderRole && session != "zasp-api-audit-read" {
			next.ServeHTTP(w, r)
			return
		}
		if len(r.Form) != 6 || r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("Version") != "2011-06-15" || role != auditBrowserProviderReaderRole || session != "zasp-api-audit-read" || r.Form.Get("WebIdentityToken") != auditExportProcessToken || r.Form.Get("DurationSeconds") != "900" || r.Header.Get("Authorization") != "" {
			http.Error(w, "owned reader authority refused", 400)
			return
		}
		for _, values := range r.Form {
			if len(values) != 1 {
				http.Error(w, "duplicate STS field", 400)
				return
			}
		}
		count.Add(1)
		credentials := auditBrowserReaderCredentials()
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, fmt.Sprintf(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken, time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339)))
	}), count
}

func TestAuditHTTPSizeProviderBrowserReaderSTSSelection(t *testing.T) {
	handler, count := auditBrowserReaderSTS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "base reader unsupported", 400) }))
	base := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "RoleArn": {auditBrowserProviderReaderRole}, "RoleSessionName": {"zasp-api-audit-read"}, "WebIdentityToken": {auditExportProcessToken}, "DurationSeconds": {"900"}}
	for _, mutation := range []string{"valid", "role", "session", "token", "duration", "extra", "duplicate", "signed"} {
		t.Run(mutation, func(t *testing.T) {
			form := url.Values{}
			for k, v := range base {
				form[k] = append([]string(nil), v...)
			}
			switch mutation {
			case "role":
				form.Set("RoleArn", "arn:aws:iam::123456789012:role/other")
			case "session":
				form.Set("RoleSessionName", "wrong")
			case "token":
				form.Set("WebIdentityToken", "wrong")
			case "duration":
				form.Set("DurationSeconds", "901")
			case "extra":
				form.Set("Other", "yes")
			case "duplicate":
				form.Add("RoleArn", auditBrowserProviderReaderRole)
			}
			req := httptest.NewRequest("POST", "https://sts.us-east-1.amazonaws.com/", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if mutation == "signed" {
				req.Header.Set("Authorization", "forged")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if mutation == "valid" {
				if response.Code != 200 || !bytes.Contains(response.Body.Bytes(), []byte("ASIABROWSERREADER")) {
					t.Fatal("selected reader exchange refused", response.Code)
				}
			} else if response.Code == 200 {
				t.Fatal("mismatched reader identity admitted")
			}
		})
	}
	if count.Load() != 1 {
		t.Fatal("reader exchange accounting differs", count.Load())
	}
}

func TestAuditHTTPSizeProviderBrowserRejectsSizeReaderFallback(t *testing.T) {
	policy := auditExportTestPolicy()
	binding := audit.ExportBinding{OrganizationID: "pid_10000001-0000-4000-8000-000000000001", WorkspaceID: "pid_10000002-0000-4000-8000-000000000002", EnvironmentID: "pid_10000003-0000-4000-8000-000000000003", ExportID: "pid_10000004-0000-4000-8000-000000000004"}
	p := &auditHTTPSizeProvider{policy: policy, browserReader: true}
	key := fmt.Sprintf("organizations/%s/workspaces/%s/environments/%s/exports/pid_10000005-0000-4000-8000-000000000005", binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID)
	request := auditHTTPSizeRequest(t, http.MethodGet, "reader", key, "?versionId=owned&x-id=GetObject", nil, binding)
	request = request.WithContext(context.Background())
	control := &auditHTTPSizeProvider{policy: policy}
	if _, _, err := control.validate(request.Clone(request.Context()), binding); err != nil {
		t.Fatal("default reader control rejected", err)
	}
	if _, _, err := p.validate(request, binding); err == nil {
		t.Fatal("selected browser silently accepted size-fixture reader credentials")
	}
}
