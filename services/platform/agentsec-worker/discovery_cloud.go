package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var (
	discoveryCloudRolePattern  = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}$`)
	discoverySecretRootPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_/-]{2,127}$`)
	discoveryWebTokenPattern   = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

type discoveryWebIdentityAPI interface {
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type discoverySecretsManagerAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type productionDiscoveryCloudConfig struct {
	Region     string
	RoleARN    string
	TokenFile  string
	SecretRoot string
	Timeout    time.Duration
	Clock      func() time.Time
}

type discoveryWebIdentityProvider struct {
	client    discoveryWebIdentityAPI
	roleARN   string
	tokenFile string
	timeout   time.Duration
	clock     func() time.Time
}

func (provider *discoveryWebIdentityProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if provider == nil || nilDiscoveryCloudDependency(provider.client) || ctx == nil || ctx.Err() != nil || !discoveryCloudRolePattern.MatchString(provider.roleARN) || provider.tokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || provider.timeout < time.Second || provider.timeout > 30*time.Second || provider.clock == nil {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	file, err := os.Open(provider.tokenFile)
	if err != nil {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	token, readErr := io.ReadAll(io.LimitReader(file, 16_385))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(token) < 64 || len(token) > 16_384 || !discoveryWebTokenPattern.Match(token) || strings.TrimSpace(string(token)) != string(token) {
		clear(token)
		return aws.Credentials{}, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	duration := int32(900)
	output, assumeErr := provider.client.AssumeRoleWithWebIdentity(bounded, &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(provider.roleARN), RoleSessionName: aws.String("zasp-discovery-worker"), WebIdentityToken: aws.String(string(token)), DurationSeconds: &duration}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	clear(token)
	now := provider.clock()
	if assumeErr != nil || bounded.Err() != nil || now.IsZero() || now.Location() != time.UTC || output == nil || output.Credentials == nil || output.Credentials.AccessKeyId == nil || output.Credentials.SecretAccessKey == nil || output.Credentials.SessionToken == nil || output.Credentials.Expiration == nil || !output.Credentials.Expiration.After(now.Add(time.Minute)) {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	return aws.Credentials{AccessKeyID: *output.Credentials.AccessKeyId, SecretAccessKey: *output.Credentials.SecretAccessKey, SessionToken: *output.Credentials.SessionToken, CanExpire: true, Expires: output.Credentials.Expiration.UTC(), Source: "zasp-discovery-web-identity"}, nil
}

type discoverySecretsManagerReader struct {
	client  discoverySecretsManagerAPI
	root    string
	timeout time.Duration
}

func newDiscoverySecretsManagerReader(client discoverySecretsManagerAPI, root string, timeout time.Duration) (*discoverySecretsManagerReader, error) {
	if nilDiscoveryCloudDependency(client) || !validDiscoverySecretRoot(root) || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, errRuntimeUnavailable
	}
	return &discoverySecretsManagerReader{client: client, root: root, timeout: timeout}, nil
}

func (reader *discoverySecretsManagerReader) ResolveDiscoverySecret(ctx context.Context, reference string) ([]byte, error) {
	if reader == nil || ctx == nil || ctx.Err() != nil || !validDiscoveryCredentialReference(reference, "ref:") {
		return nil, errDiscoveryCredentialUnavailable
	}
	parts := strings.SplitN(strings.TrimPrefix(reference, "ref:"), "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, errDiscoveryCredentialUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, reader.timeout)
	defer cancel()
	output, err := reader.client.GetSecretValue(bounded, &secretsmanager.GetSecretValueInput{SecretId: aws.String(reader.root + "/" + parts[0] + "/" + parts[1]), VersionStage: aws.String("AWSCURRENT")}, func(options *secretsmanager.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || bounded.Err() != nil || output == nil || output.SecretString != nil == (len(output.SecretBinary) > 0) {
		return nil, errDiscoveryCredentialUnavailable
	}
	var value []byte
	if output.SecretString != nil {
		value = []byte(*output.SecretString)
	} else {
		value = append([]byte(nil), output.SecretBinary...)
	}
	if len(value) < 1 || len(value) > 32<<10 {
		clear(value)
		return nil, errDiscoveryCredentialUnavailable
	}
	return value, nil
}

type productionDiscoveryCloudAuthority struct {
	base        aws.Config
	credentials aws.CredentialsProvider
	secrets     *secretsmanager.Client
	assumeRole  *sts.Client
	s3          *s3.Client
	transport   *http.Transport
	clock       func() time.Time
	closeOnce   sync.Once
}

func newProductionDiscoveryCloudAuthority(config productionDiscoveryCloudConfig) (*productionDiscoveryCloudAuthority, error) {
	if !validProductionDiscoveryCloudConfig(config) {
		return nil, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 1 << 20}
	httpClient := &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: rejectDiscoveryProviderRedirect}
	base := aws.Config{Region: config.Region, HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	webIdentity := &discoveryWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.RoleARN, tokenFile: config.TokenFile, timeout: config.Timeout, clock: config.Clock}
	credentials := aws.NewCredentialsCache(webIdentity)
	base.Credentials = credentials
	return &productionDiscoveryCloudAuthority{base: base, credentials: credentials, secrets: secretsmanager.NewFromConfig(base), assumeRole: sts.NewFromConfig(base), s3: s3.NewFromConfig(base), transport: transport, clock: config.Clock}, nil
}

func (authority *productionDiscoveryCloudAuthority) NewCallerIdentity(region string, credentials aws.Credentials) (discoveryCallerIdentityAPI, error) {
	if authority == nil || authority.transport == nil || authority.clock == nil || !discoveryRegionPattern.MatchString(region) || !credentials.HasKeys() || !credentials.CanExpire || !credentials.Expires.After(authority.clock()) {
		return nil, errRuntimeUnavailable
	}
	base := authority.base
	base.Region = region
	base.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return credentials, nil })
	return sts.NewFromConfig(base), nil
}

func (authority *productionDiscoveryCloudAuthority) Close() error {
	if authority == nil {
		return nil
	}
	authority.closeOnce.Do(func() {
		if authority.transport != nil {
			authority.transport.CloseIdleConnections()
		}
	})
	return nil
}

func validProductionDiscoveryCloudConfig(config productionDiscoveryCloudConfig) bool {
	if !discoveryRegionPattern.MatchString(config.Region) || !discoveryCloudRolePattern.MatchString(config.RoleARN) || config.TokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || !validDiscoverySecretRoot(config.SecretRoot) || config.Timeout < time.Second || config.Timeout > 30*time.Second || config.Clock == nil {
		return false
	}
	now := config.Clock()
	return !now.IsZero() && now.Location() == time.UTC
}

func validDiscoverySecretRoot(value string) bool {
	return discoverySecretRootPattern.MatchString(value) && !strings.Contains(value, "..") && !strings.Contains(value, "//") && !strings.HasSuffix(value, "/") && !strings.HasSuffix(value, "/oauth")
}

func nilDiscoveryCloudDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

var _ aws.CredentialsProvider = (*discoveryWebIdentityProvider)(nil)
var _ discoverySecretReader = (*discoverySecretsManagerReader)(nil)
