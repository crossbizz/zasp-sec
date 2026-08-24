package redteamadapter

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var (
	awsRegionRE = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$`)
	awsRoleRE   = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]{1,128})$`)
	webTokenRE  = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

type AssumeRoleAPI interface {
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type IdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type CloudConfig struct {
	Region                       string
	RoleARN                      string
	WebIdentityTokenFile         string
	ReadinessCredentialReference string
	Timeout                      time.Duration
	Clock                        func() time.Time
}

type CloudAuthority struct {
	credentials aws.CredentialsProvider
	identity    IdentityAPI
	resolver    *SecretsCredentialResolver
	config      CloudConfig
	transport   *http.Transport
	closeOnce   sync.Once
}

type webIdentityProvider struct {
	client    AssumeRoleAPI
	roleARN   string
	tokenFile string
	timeout   time.Duration
	clock     func() time.Time
}

func (provider *webIdentityProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if provider == nil || provider.client == nil || ctx == nil || ctx.Err() != nil || !awsRoleRE.MatchString(provider.roleARN) || provider.tokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || provider.timeout < time.Second || provider.timeout > 30*time.Second || provider.clock == nil {
		return aws.Credentials{}, ErrAdapter
	}
	file, err := os.Open(provider.tokenFile)
	if err != nil {
		return aws.Credentials{}, ErrAdapter
	}
	token, readErr := io.ReadAll(io.LimitReader(file, 16_385))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(token) < 64 || len(token) > 16_384 || !webTokenRE.Match(token) || strings.TrimSpace(string(token)) != string(token) {
		clear(token)
		return aws.Credentials{}, ErrAdapter
	}
	bounded, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	duration := int32(900)
	output, assumeErr := provider.client.AssumeRoleWithWebIdentity(bounded, &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(provider.roleARN), RoleSessionName: aws.String("zasp-red-team-adapter"), WebIdentityToken: aws.String(string(token)), DurationSeconds: &duration}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	clear(token)
	now := provider.clock()
	if assumeErr != nil || bounded.Err() != nil || now.IsZero() || now.Location() != time.UTC || output == nil || output.Credentials == nil || output.Credentials.AccessKeyId == nil || output.Credentials.SecretAccessKey == nil || output.Credentials.SessionToken == nil || output.Credentials.Expiration == nil || !output.Credentials.Expiration.After(now.Add(time.Minute)) {
		return aws.Credentials{}, ErrAdapter
	}
	return aws.Credentials{AccessKeyID: *output.Credentials.AccessKeyId, SecretAccessKey: *output.Credentials.SecretAccessKey, SessionToken: *output.Credentials.SessionToken, CanExpire: true, Expires: output.Credentials.Expiration.UTC(), Source: "zasp-red-team-adapter-web-identity"}, nil
}

func NewProductionCloudAuthority(config CloudConfig) (*CloudAuthority, error) {
	if !validCloudConfig(config) {
		return nil, ErrAdapter
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 64 << 10}
	httpClient := &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrAdapter }}
	base := aws.Config{Region: config.Region, HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	credentials := aws.NewCredentialsCache(&webIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.RoleARN, tokenFile: config.WebIdentityTokenFile, timeout: config.Timeout, clock: config.Clock})
	base.Credentials = credentials
	resolver, err := NewSecretsCredentialResolver(secretsmanager.NewFromConfig(base), "zasp/red-team/targets", config.Timeout)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, ErrAdapter
	}
	return &CloudAuthority{credentials: credentials, identity: sts.NewFromConfig(base), resolver: resolver, config: config, transport: transport}, nil
}

func (authority *CloudAuthority) CredentialResolver() CredentialResolver {
	if authority == nil {
		return nil
	}
	return authority.resolver
}

func (authority *CloudAuthority) Ready(ctx context.Context) error {
	if authority == nil || authority.credentials == nil || authority.identity == nil || authority.resolver == nil || ctx == nil || ctx.Err() != nil || !validCloudConfig(authority.config) {
		return ErrAdapter
	}
	if _, err := authority.credentials.Retrieve(ctx); err != nil {
		return ErrAdapter
	}
	bounded, cancel := context.WithTimeout(ctx, authority.config.Timeout)
	defer cancel()
	identity, err := authority.identity.GetCallerIdentity(bounded, &sts.GetCallerIdentityInput{}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	matches := awsRoleRE.FindStringSubmatch(authority.config.RoleARN)
	roleName := ""
	if len(matches) == 3 {
		parts := strings.Split(matches[2], "/")
		roleName = parts[len(parts)-1]
	}
	expectedARN := "arn:aws:sts::" + matches[1] + ":assumed-role/" + roleName + "/zasp-red-team-adapter"
	if err != nil || bounded.Err() != nil || identity == nil || aws.ToString(identity.Account) != matches[1] || aws.ToString(identity.Arn) != expectedARN {
		return ErrAdapter
	}
	credential, err := authority.resolver.ResolveTargetCredential(ctx, authority.config.ReadinessCredentialReference)
	if err != nil || credential == nil {
		if credential != nil {
			credential.Destroy()
		}
		return ErrAdapter
	}
	credential.Destroy()
	return nil
}

func (authority *CloudAuthority) Close() {
	if authority == nil {
		return
	}
	authority.closeOnce.Do(func() {
		if authority.transport != nil {
			authority.transport.CloseIdleConnections()
		}
	})
}

func validCloudConfig(config CloudConfig) bool {
	return awsRegionRE.MatchString(config.Region) && awsRoleRE.MatchString(config.RoleARN) && config.WebIdentityTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" && credentialReferenceRE.MatchString(config.ReadinessCredentialReference) && config.Timeout >= time.Second && config.Timeout <= 30*time.Second && config.Clock != nil
}

func ValidCloudConfig(config CloudConfig) bool { return validCloudConfig(config) }

var _ aws.CredentialsProvider = (*webIdentityProvider)(nil)
