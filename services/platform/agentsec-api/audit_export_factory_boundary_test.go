package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func auditFactoryProvider() apiserver.CallbackProvider {
	return apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
		return apiserver.SessionGrant{}, errors.New("unused owned identity callback")
	})
}

// Removing entry validation must not open a database or invoke storage authority.
func TestAuditExportFactoryRejectsInvalidAuthorityBeforeIO(t *testing.T) {
	for _, entry := range []string{"build", "compose"} {
		for _, scenario := range []string{"nil-context", "cancelled", "invalid-config", "nil-factory"} {
			t.Run(entry+"/"+scenario, func(t *testing.T) {
				config := fixtureAuditExportRuntimeConfig(t)
				ctx := context.Background()
				calls := 0
				var factory auditExportStorageFactory = func(RuntimeConfig) ([]apiserver.AuditExportStorageConfiguration, *http.Transport, error) {
					calls++
					return nil, nil, errors.New("unexpected storage construction")
				}
				switch scenario {
				case "nil-context":
					ctx = nil
				case "cancelled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				case "invalid-config":
					config.ProviderTimeout = 0
				case "nil-factory":
					factory = nil
				}
				db := &auditExportRuntimeDatabase{gate: json.RawMessage(`true`)}
				var deps RuntimeDependencies
				var err error
				if entry == "build" {
					deps, err = buildRuntimeDependenciesWithAuditExportStorage(ctx, config, factory)
				} else {
					deps, err = composeRuntimeDependenciesWithAuditExportStorage(ctx, config, db, db, auditFactoryProvider(), factory)
				}
				for _, closer := range deps.Closers {
					_ = closer.Close()
				}
				if err != errRuntimeUnavailable || deps.ProductHandler != nil || len(deps.Closers) != 0 || calls != 0 || len(db.queries) != 0 {
					t.Fatalf("invalid authority reached resources: err=%v calls=%d queries=%v", err, calls, db.queries)
				}
			})
		}
	}
}

// Moving build validation below database construction must reach this owned trap.
func TestAuditExportFactoryBuildRejectsAuthorityBeforeDatabaseDial(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	for _, scenario := range []string{"invalid-config", "nil-factory"} {
		t.Run(scenario, func(t *testing.T) {
			config := fixtureAuditExportRuntimeConfig(t)
			config.PostgresDSN = "postgres://zasp@" + server.Listener.Addr().String() + "/zasp?sslmode=require"
			config.SecurityAgentPostgresDSN = "postgres://zasp_security_agent_api@" + server.Listener.Addr().String() + "/zasp?sslmode=require"
			config.ProviderTimeout = 100 * time.Millisecond
			if !validRuntimeConfig(config) {
				t.Fatal("owned database trap needs valid authority")
			}
			var factory auditExportStorageFactory = newAuditExportStorageClients
			if scenario == "invalid-config" {
				config.PublicOrigin = "invalid"
			} else {
				factory = nil
			}
			deps, err := buildRuntimeDependenciesWithAuditExportStorage(context.Background(), config, factory)
			for _, closer := range deps.Closers {
				_ = closer.Close()
			}
			if err != errRuntimeUnavailable || connections.Load() != 0 {
				t.Fatalf("invalid build authority dialed database: err=%v connections=%d", err, connections.Load())
			}
		})
	}
}

// Ignoring the injected factory or bypassing mounted permission checks breaks this.
func TestAuditExportFactoryFullCompositionCapability(t *testing.T) {
	t.Setenv("HOSTNAME", "audit-factory-owned")
	for _, installed := range []bool{false, true} {
		for _, permitted := range []bool{false, true} {
			config := fixtureAuditExportRuntimeConfig(t)
			if !installed {
				config.AuditExports = nil
			}
			calls := 0
			factory := func(got RuntimeConfig) ([]apiserver.AuditExportStorageConfiguration, *http.Transport, error) {
				calls++
				if got.AuditExports != config.AuditExports {
					t.Fatal("factory lost configured authority")
				}
				return newAuditExportStorageClients(got)
			}
			db := &auditExportRuntimeDatabase{gate: json.RawMessage(`true`), permissions: []string{"view"}}
			if permitted {
				db.permissions = append(db.permissions, "view_audit")
			}
			deps, err := composeRuntimeDependenciesWithAuditExportStorage(context.Background(), config, db, db, auditFactoryProvider(), factory)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				for _, closer := range deps.Closers {
					_ = closer.Close()
				}
			})
			wantCalls := 0
			if installed {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("installed=%t factory calls=%d want=%d", installed, calls, wantCalls)
			}
			response := httptest.NewRecorder()
			deps.ProductHandler.ServeHTTP(response, publicPageRuntimeRequest(config, "/api/v1/session/bootstrap"))
			var bootstrap struct {
				Capabilities []string `json:"capabilities"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &bootstrap) != nil {
				t.Fatalf("bootstrap %d %s", response.Code, response.Body.String())
			}
			if slices.Contains(bootstrap.Capabilities, "audit.exports") != (installed && permitted) || slices.Contains(bootstrap.Capabilities, "audit.read") != permitted {
				t.Fatal("mounted capability lost installation/permission intersection", bootstrap.Capabilities)
			}
		}
	}
}

// Omitting transport ownership on any exit leaves the task-owned connection open.
func TestAuditExportFactoryOwnsReturnedTransport(t *testing.T) {
	t.Setenv("HOSTNAME", "audit-factory-owned")
	for _, scenario := range []string{"factory-error", "readiness-error", "late-cancellation", "empty-storage", "malformed-storage", "nil-transport", "success"} {
		t.Run(scenario, func(t *testing.T) {
			closed := make(chan struct{}, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					select {
					case closed <- struct{}{}:
					default:
					}
				}
			}
			server.Start()
			defer server.Close()
			config := fixtureAuditExportRuntimeConfig(t)
			entries, transport, err := newAuditExportStorageClients(config)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			db := &auditExportRuntimeDatabase{gate: json.RawMessage(`true`)}
			if scenario == "readiness-error" {
				db.gate = json.RawMessage(`false`)
			}
			if scenario == "late-cancellation" {
				db.afterExport = cancel
			}
			calls := 0
			factory := func(RuntimeConfig) ([]apiserver.AuditExportStorageConfiguration, *http.Transport, error) {
				calls++
				switch scenario {
				case "factory-error":
					return entries, transport, errors.New("owned construction failure")
				case "empty-storage":
					return nil, transport, nil
				case "malformed-storage":
					entries[0].Client = nil
				case "nil-transport":
					return entries, nil, nil
				}
				return entries, transport, nil
			}
			deps, err := composeRuntimeDependenciesWithAuditExportStorage(ctx, config, db, db, auditFactoryProvider(), factory)
			if calls != 1 {
				t.Errorf("factory calls=%d", calls)
			}
			if scenario == "success" {
				if err != nil || deps.ProductHandler == nil {
					t.Fatalf("composition: %v", err)
				}
				select {
				case <-closed:
					t.Fatal("successful composition closed owned transport early")
				default:
				}
			} else if err != errRuntimeUnavailable || deps.ProductHandler != nil || len(deps.Closers) != 0 {
				t.Errorf("failed composition transferred dependencies: %v", err)
			}
			for _, closer := range deps.Closers {
				if err := closer.Close(); err != nil {
					t.Error(err)
				}
			}
			if scenario == "nil-transport" {
				return
			} // That connection was never returned to composition.
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Error("composition left returned transport connection open")
			}
		})
	}
}

// Rebuilding credentials instead of retaining the cached clients' providers fails the read.
func TestAuditExportFactoryResourcesUseExactCachedProviders(t *testing.T) {
	for _, key := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL_STS", "AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_REGION", "AWS_DEFAULT_REGION", "HTTPS_PROXY"} {
		t.Setenv(key, "invalid-ambient-authority")
	}
	config := fixtureAuditExportRuntimeConfig(t)
	config.ProviderTimeout = time.Second
	resources, err := newAuditExportStorageResources(config)
	if err != nil {
		t.Fatal(err)
	}
	if resources.transport != nil {
		defer resources.transport.CloseIdleConnections()
	}
	if len(resources.entries) != 1 || len(resources.credentials) != 1 || resources.credentials[0] == nil {
		t.Fatal("factory did not retain the exact credential providers")
	}
	token := strings.Repeat("owned-token-", 8)
	path := filepath.Join(t.TempDir(), "projected-token")
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	var stsCalls, s3Calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "sts.us-east-1.amazonaws.com":
			stsCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("Version") != "2011-06-15" || r.Form.Get("RoleArn") != "arn:aws:iam::123456789012:role/zasp-audit-export-reader" || r.Form.Get("RoleSessionName") != "zasp-api-audit-read" || r.Form.Get("WebIdentityToken") != token || r.Form.Get("DurationSeconds") != "900" || r.Header.Get("Authorization") != "" {
				t.Error("STS authority changed")
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAOWNED000000000001</AccessKeyId><SecretAccessKey>owned-test-secret-not-real</SecretAccessKey><SessionToken>owned-session-token-not-real</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
		case "audit-exports-owned.s3.us-east-1.amazonaws.com":
			s3Calls.Add(1)
			if r.Method != http.MethodGet || r.URL.Path != "/exports/owned" || r.URL.Query().Get("versionId") != "owned-version" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" || r.Header.Get("X-Amz-Security-Token") != "owned-session-token-not-real" || !strings.Contains(r.Header.Get("Authorization"), "Credential=ASIAOWNED000000000001/") || !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/s3/aws4_request") {
				t.Error("S3 authority changed")
				w.WriteHeader(400)
				return
			}
			w.Header().Set("X-Amz-Version-Id", "owned-version")
			_, _ = io.WriteString(w, "owned")
		default:
			t.Error("unexpected SDK authority", r.Host)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	resources.credentials[0].tokenFile = path
	resources.transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, ServerName: "example.com"}
	resources.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "sts.us-east-1.amazonaws.com:443" && address != "audit-exports-owned.s3.us-east-1.amazonaws.com:443" {
			return nil, errors.New("unexpected external address")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client := resources.entries[0].Client.(*s3.Client)
	// Both real SDKs share this owned client. Observe deadlines without replacing
	// either SDK or the TLS exchange below it.
	client.Options().HTTPClient.(*http.Client).Transport = auditExportCredentialTransport(func(request *http.Request) (*http.Response, error) {
		deadline, bounded := request.Context().Deadline()
		if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
			return nil, errors.New("factory SDK request has no bounded deadline")
		}
		return resources.transport.RoundTrip(request)
	})
	for range 2 {
		out, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String("audit-exports-owned"), Key: aws.String("exports/owned"), VersionId: aws.String("owned-version"), ExpectedBucketOwner: aws.String("123456789012")})
		if err != nil {
			t.Fatal("actual factory SDK read failed", err)
		}
		body, readErr := io.ReadAll(out.Body)
		closeErr := out.Body.Close()
		if readErr != nil || closeErr != nil || string(body) != "owned" || aws.ToString(out.VersionId) != "owned-version" {
			t.Fatal("pinned bytes changed")
		}
	}
	if stsCalls.Load() != 1 || s3Calls.Load() != 2 {
		t.Fatal("factory cache was not shared", stsCalls.Load(), s3Calls.Load())
	}
	config.AuditExports.TokenFile = path
	invalid, err := newAuditExportStorageResources(config)
	if err != errRuntimeUnavailable || invalid.transport != nil || len(invalid.entries) != 0 || len(invalid.credentials) != 0 {
		t.Fatal("production resources accepted owned temporary token path")
	}
}
