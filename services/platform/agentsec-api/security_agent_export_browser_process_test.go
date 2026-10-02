package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/exportfixture"
)

type exportBrowserReadinessTransport struct {
	port  string
	inner http.RoundTripper
}

func (transport exportBrowserReadinessTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || transport.inner == nil {
		return nil, errors.New("owned readiness request missing")
	}
	_, bounded := request.Context().Deadline()
	allowed := false
	for _, host := range []string{"agentsec-security-agent:8081", "agentsec-security-agent-action:8081", "zasp-compliance-export-worker:8081", "zasp-compliance-cleanup-worker:8081"} {
		if request.URL.Host == host {
			allowed = true
		}
	}
	if !bounded || request.Context().Err() != nil || !allowed || request.Method != http.MethodGet || request.URL.Scheme != "http" || request.URL.Path != "/readyz" || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.URL.User != nil || request.Host != "" && request.Host != request.URL.Host {
		return nil, errors.New("owned readiness destination refused")
	}
	port, err := strconv.Atoi(transport.port)
	if err != nil || port < 1024 || port > 65535 || strconv.Itoa(port) != transport.port {
		return nil, errors.New("owned readiness port refused")
	}
	copy := request.Clone(request.Context())
	copy.Host = request.URL.Host
	copy.URL.Host = "127.0.0.1:" + transport.port
	return transport.inner.RoundTrip(copy)
}

// Keeps real Stytch callback/session middleware, registered repositories and
// mounted retrieval. Only external S3 transport and private service placement
// are controlled. No injected RequestIdentity or product-state fixtures.
func TestSecurityAgentExportBrowserAPIProcess(t *testing.T) {
	if os.Getenv("ZASP_SA_EXPORT_BROWSER_API") != "true" {
		t.Skip("owned export browser parent only")
	}
	config, err := loadRuntimeConfigFromEnvironment(os.LookupEnv)
	if err != nil || config.Environment != "test" || config.EvidenceExportWorkflow != "enabled" || config.ComplianceExports == nil || config.AuditExports != nil || auditBrowserProcessInputs(config, os.Getenv("ZASP_SA_EXPORT_BROWSER_PG_PORT")) != nil {
		t.Fatal("owned export browser API configuration refused", err)
	}
	deadline, err := time.Parse(time.RFC3339Nano, os.Getenv("ZASP_SA_EXPORT_BROWSER_DEADLINE"))
	if err != nil || time.Until(deadline) < time.Second || time.Until(deadline) > 30*time.Minute {
		t.Fatal("owned export browser deadline refused")
	}
	storePath := os.Getenv("ZASP_SA_EXPORT_BROWSER_OBJECT")
	if !filepath.IsAbs(storePath) || filepath.Clean(storePath) != storePath || filepath.Base(storePath) != "export-store" || !strings.HasPrefix(filepath.Base(filepath.Dir(storePath)), "zasp-production-e2e-") {
		t.Fatal("owned export browser store path refused")
	}
	store, err := exportfixture.Open(exportfixture.Config{Directory: storePath, Bucket: config.ComplianceExports.Bucket, Owner: config.ComplianceExports.Owner, KMSKey: config.ComplianceExports.KMSKey, MaximumBytes: 8 << 20})
	if err != nil {
		t.Fatal("owned export browser storage refused", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	port := os.Getenv("ZASP_SA_EXPORT_BROWSER_WORKER_PORT")
	number, err := strconv.Atoi(port)
	if err != nil || number < 1024 || number > 65535 || strconv.Itoa(number) != port {
		t.Fatal("owned export worker port refused")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	inner := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, ResponseHeaderTimeout: time.Second}
	defer inner.CloseIdleConnections()
	factory := func(c RuntimeConfig) (complianceStorageResources, error) {
		provider := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://controlled.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, Retryer: aws.NopRetryer{}, HTTPClient: &http.Client{Transport: store.Transport(exportfixture.Options{ReadOnly: true}), Timeout: c.ProviderTimeout}})
		p := c.ComplianceExports
		return complianceStorageResources{config: apiserver.ComplianceHandlerConfiguration{Bucket: p.Bucket, ExpectedBucketOwner: p.Owner, KMSKeyARN: p.KMSKey, Client: provider, ProviderTimeout: c.ProviderTimeout}, transport: &http.Transport{}}, nil
	}
	deps, err := buildRuntimeDependenciesWithReadinessTransport(ctx, config, newAuditExportStorageClients, factory, exportBrowserReadinessTransport{port: port, inner: inner})
	if err != nil {
		t.Fatal("actual export API composition refused", err)
	}
	if err = serveRuntime(ctx, os.Stdout, "security-agent-export-browser", config, deps, net.Listen); err != nil {
		t.Fatal("actual export API lifecycle failed", err)
	}
	t.Log("owned export browser API joined")
}

type exportBrowserRoundTripFunc func(*http.Request) (*http.Response, error)

func (f exportBrowserRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSecurityAgentExportBrowserReadinessDestinations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	expectedHost := "agentsec-security-agent:8081"
	transport := exportBrowserReadinessTransport{port: "15438", inner: exportBrowserRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "127.0.0.1:15438" || r.Host != expectedHost {
			t.Errorf("readiness route lost owned endpoint/Host: %s %s", r.URL, r.Host)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ready")), Header: make(http.Header)}, nil
	})}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://foreign.invalid:8081/readyz", nil)
	if _, err := transport.RoundTrip(request); err == nil || calls != 0 {
		t.Fatal("foreign readiness request reached transport")
	}
	for _, target := range []string{"http://agentsec-security-agent:8081/readyz?probe=1", "https://agentsec-security-agent:8081/readyz", "http://agentsec-security-agent:8081/other"} {
		request, _ = http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if _, err := transport.RoundTrip(request); err == nil {
			t.Fatal("unexpected readiness request accepted", target)
		}
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodPost, "http://agentsec-security-agent:8081/readyz", nil)
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("readiness mutation accepted")
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, "http://agentsec-security-agent:8081/readyz", nil)
	response, err := transport.RoundTrip(request)
	if err != nil || response.StatusCode != 200 || calls != 1 {
		t.Fatal("owned readiness failed", err, calls)
	}
	response.Body.Close()
	for _, host := range []string{"agentsec-security-agent-action:8081", "zasp-compliance-export-worker:8081", "zasp-compliance-cleanup-worker:8081"} {
		expectedHost = host
		request, _ = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/readyz", nil)
		response, err = transport.RoundTrip(request)
		if err != nil || response.StatusCode != 200 || request.URL.Host != host {
			t.Fatal("fixed service readiness refused or mutated original request", err)
		}
		response.Body.Close()
	}
	if calls != 4 {
		t.Fatal("fixed readiness destinations were not all probed", calls)
	}
	unbounded, _ := http.NewRequest(http.MethodGet, "http://agentsec-security-agent:8081/readyz", nil)
	if _, err = transport.RoundTrip(unbounded); err == nil {
		t.Fatal("unbounded readiness forwarded")
	}
	for _, port := range []string{"", "08081", "1", "65536", "foreign:8081"} {
		bad := transport
		bad.port = port
		if _, err = bad.RoundTrip(request); err == nil {
			t.Fatal("invalid port forwarded", port)
		}
	}
	if calls != 4 {
		t.Fatal("refused request reached transport")
	}
}
