package main

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func fixtureAuditExportRuntimeConfig(t *testing.T) RuntimeConfig {
	t.Helper()
	values := fixtureAuditExportEnvironment()
	config, err := loadRuntimeConfigFromEnvironment(func(key string) (string, bool) { value, ok := values[key]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestAuditExportAWSClientsUseExplicitHistoricalAuthority(t *testing.T) {
	for _, key := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL_STS", "AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_REGION", "AWS_DEFAULT_REGION", "HTTPS_PROXY"} {
		t.Setenv(key, "invalid-ambient-authority")
	}
	config := fixtureAuditExportRuntimeConfig(t)
	second := config.AuditExports.Policies[0]
	second.PolicyID = "pid_52000002-0000-4000-8000-000000000002"
	second.KMSKeyARN = strings.Replace(second.KMSKeyARN, "us-east-1", "eu-west-1", 1)
	config.AuditExports.Policies = append(config.AuditExports.Policies, second)
	entries, transport, err := newAuditExportStorageClients(config)
	if err != nil || transport == nil || len(entries) != 2 {
		t.Fatal("owned explicit clients unavailable", err)
	}
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil || transport.DialContext == nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || transport.ResponseHeaderTimeout != config.ProviderTimeout || transport.TLSHandshakeTimeout <= 0 || transport.MaxResponseHeaderBytes != 1<<20 {
		t.Fatal("provider transport permits ambient or unbounded behavior")
	}
	for index, region := range []string{"us-east-1", "eu-west-1"} {
		client, ok := entries[index].Client.(*s3.Client)
		if !ok || entries[index].Policy != config.AuditExports.Policies[index] {
			t.Fatal("policy/client authority changed")
		}
		options := client.Options()
		owned, ok := options.HTTPClient.(*http.Client)
		if !ok || owned.Transport != transport || owned.Timeout != config.ProviderTimeout || options.Region != region || options.BaseEndpoint != nil || options.UsePathStyle || options.Retryer.MaxAttempts() != 1 {
			t.Fatal("SDK ignored explicit region/transport/retry authority")
		}
		if owned.CheckRedirect == nil || owned.CheckRedirect(&http.Request{}, nil) != http.ErrUseLastResponse {
			t.Fatal("provider follows redirects")
		}
		if _, ok := options.Credentials.(*aws.CredentialsCache); !ok {
			t.Fatal("provider uses ambient credentials")
		}
	}
	config.AuditExports.Policies[0].Bucket = "changed"
	if entries[0].Policy.Bucket != "audit-exports-owned" {
		t.Fatal("client policy aliases mutable config")
	}
	transport.CloseIdleConnections()
}

func TestAuditExportAWSClientsRejectInvalidConfiguration(t *testing.T) {
	for _, kind := range []string{"disabled", "role", "key", "region", "late region", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			config := fixtureAuditExportRuntimeConfig(t)
			switch kind {
			case "disabled":
				config.AuditExports = nil
			case "role":
				config.AuditExports.ReaderRoleARN = "invalid"
			case "key":
				clear(config.AuditExports.CursorSigningKey)
			case "region":
				config.AuditExports.Policies[0].KMSKeyARN = strings.Replace(config.AuditExports.Policies[0].KMSKeyARN, "us-east-1", "x", 1)
			case "late region":
				second := config.AuditExports.Policies[0]
				second.PolicyID = "pid_52000002-0000-4000-8000-000000000002"
				second.KMSKeyARN = strings.Replace(second.KMSKeyARN, "us-east-1", "x", 1)
				config.AuditExports.Policies = append(config.AuditExports.Policies, second)
			case "timeout":
				config.ProviderTimeout = 0
			}
			entries, transport, err := newAuditExportStorageClients(config)
			if err != errRuntimeUnavailable || entries != nil || transport != nil {
				t.Fatal("invalid construction returned authority/resources")
			}
		})
	}
}

func TestAuditExportWebIdentitySessionIsClosed(t *testing.T) {
	for _, label := range []string{"", "zasp-api-connectors", "zasp-api-audit-read", "other", " zasp-api-audit-read"} {
		provider := &connectorWebIdentityProvider{sessionName: label}
		name, ok := provider.session()
		valid := label == "" || label == "zasp-api-connectors" || label == "zasp-api-audit-read"
		want := label
		if label == "" {
			want = "zasp-api-connectors"
		}
		if ok != valid || valid && name != want || !valid && name != "" {
			t.Fatal("uncontrolled STS session label", label)
		}
	}
	var missing *connectorWebIdentityProvider
	if _, ok := missing.session(); ok {
		t.Fatal("nil provider session accepted")
	}
}
