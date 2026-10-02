package main

import (
	"crypto/tls"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/awsclient"
	platformconfig "github.com/zasp-ai/zasp-sec/services/platform/config"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type complianceAPIRuntimeConfig struct{ Bucket, Owner, KMSKey, ReaderRoleARN, TokenFile string }

func loadComplianceAPIConfiguration(lookup func(string) (string, bool)) (*complianceAPIRuntimeConfig, error) {
	if _, present := lookup("ZASP_COMPLIANCE_EXPORT_ROLE_ARN"); present {
		return nil, errInvalidRuntimeConfig
	}
	keys := []string{"ZASP_COMPLIANCE_EXPORT_BUCKET", "ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER", "ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN", "ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN", "ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE"}
	values := make([]string, len(keys))
	present := 0
	for i, k := range keys {
		v, ok := lookup(k)
		if ok {
			if v == "" {
				return nil, errInvalidRuntimeConfig
			}
			present++
		}
		values[i] = v
	}
	if present == 0 {
		return nil, nil
	}
	if present != len(keys) {
		return nil, errInvalidRuntimeConfig
	}
	return &complianceAPIRuntimeConfig{values[0], values[1], values[2], values[3], values[4]}, nil
}
func validComplianceAPIConfiguration(c RuntimeConfig) bool {
	p := c.ComplianceExports
	if p == nil {
		return true
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`).MatchString(p.Bucket) || !regexp.MustCompile(`^[0-9]{12}$`).MatchString(p.Owner) || !regexp.MustCompile(`^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(p.KMSKey) || !connectorRolePattern.MatchString(p.ReaderRoleARN) || p.ReaderRoleARN == c.ConnectorRoleARN || c.AuditExports != nil && p.ReaderRoleARN == c.AuditExports.ReaderRoleARN || p.TokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" {
		return false
	}
	kms := strings.Split(p.KMSKey, ":")
	role := strings.Split(p.ReaderRoleARN, ":")
	_, err := platformconfig.ParseAWSRegion(kms[3])
	return err == nil && kms[4] == p.Owner && len(role) == 6 && role[4] == p.Owner
}

type complianceStorageResources struct {
	config      apiserver.ComplianceHandlerConfiguration
	transport   *http.Transport
	credentials *connectorWebIdentityProvider
}

func newComplianceStorageResources(c RuntimeConfig) (complianceStorageResources, error) {
	if !validRuntimeConfig(c) || c.ComplianceExports == nil {
		return complianceStorageResources{}, errRuntimeUnavailable
	}
	p := c.ComplianceExports
	region, err := platformconfig.ParseAWSRegion(strings.Split(p.KMSKey, ":")[3])
	if err != nil {
		return complianceStorageResources{}, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: c.ProviderTimeout, MaxResponseHeaderBytes: 1 << 20}
	client := &http.Client{Transport: transport, Timeout: c.ProviderTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: region.String(), HTTPClient: client, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	provider := &connectorWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: p.ReaderRoleARN, tokenFile: p.TokenFile, timeout: c.ProviderTimeout, sessionName: "zasp-api-compliance-read"}
	clients, err := awsclient.New(awsclient.Options{Mode: awsclient.ModeProduction, Region: region, Credentials: aws.NewCredentialsCache(provider), HTTPClient: client})
	if err != nil {
		transport.CloseIdleConnections()
		return complianceStorageResources{}, errRuntimeUnavailable
	}
	return complianceStorageResources{config: apiserver.ComplianceHandlerConfiguration{Bucket: p.Bucket, ExpectedBucketOwner: p.Owner, KMSKeyARN: p.KMSKey, Client: clients.S3(), ProviderTimeout: c.ProviderTimeout}, transport: transport, credentials: provider}, nil
}
