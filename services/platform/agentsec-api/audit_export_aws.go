package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/awsclient"
	platformconfig "github.com/zasp-ai/zasp-sec/services/platform/config"
)

type auditExportStorageResources struct {
	entries     []apiserver.AuditExportStorageConfiguration
	transport   *http.Transport
	credentials []*connectorWebIdentityProvider
}

// The caller owns the returned transport and must close idle connections on
// shutdown and on later composition failure. Construction performs no I/O.
func newAuditExportStorageClients(config RuntimeConfig) ([]apiserver.AuditExportStorageConfiguration, *http.Transport, error) {
	resources, err := newAuditExportStorageResources(config)
	return resources.entries, resources.transport, err
}

func newAuditExportStorageResources(config RuntimeConfig) (auditExportStorageResources, error) {
	if !validRuntimeConfig(config) || config.AuditExports == nil {
		return auditExportStorageResources{}, errRuntimeUnavailable
	}
	regions := make([]platformconfig.AWSRegion, len(config.AuditExports.Policies))
	for index, policy := range config.AuditExports.Policies {
		// Only the validated operator policy reaches here, never a SQL response.
		parts := strings.Split(policy.KMSKeyARN, ":")
		if len(parts) != 6 {
			return auditExportStorageResources{}, errRuntimeUnavailable
		}
		region, err := platformconfig.ParseAWSRegion(parts[3])
		if err != nil {
			return auditExportStorageResources{}, errRuntimeUnavailable
		}
		regions[index] = region
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: config.ProviderTimeout, MaxResponseHeaderBytes: 1 << 20}
	httpClient := &http.Client{Transport: transport, Timeout: config.ProviderTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	entries := make([]apiserver.AuditExportStorageConfiguration, 0, len(regions))
	providers := make([]*connectorWebIdentityProvider, 0, len(regions))
	for index, region := range regions {
		base := aws.Config{Region: region.String(), HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
		provider := &connectorWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.AuditExports.ReaderRoleARN, tokenFile: config.AuditExports.TokenFile, timeout: config.ProviderTimeout, sessionName: "zasp-api-audit-read"}
		credentials := aws.NewCredentialsCache(provider)
		clients, err := awsclient.New(awsclient.Options{Mode: awsclient.ModeProduction, Region: region, Credentials: credentials, HTTPClient: httpClient})
		if err != nil {
			transport.CloseIdleConnections()
			return auditExportStorageResources{}, errRuntimeUnavailable
		}
		providers = append(providers, provider)
		entries = append(entries, apiserver.AuditExportStorageConfiguration{Policy: config.AuditExports.Policies[index], Client: clients.S3()})
	}
	return auditExportStorageResources{entries: entries, transport: transport, credentials: providers}, nil
}
