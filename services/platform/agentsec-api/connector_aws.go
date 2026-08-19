package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

var webIdentityTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

type secretsManagerAPI interface {
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	DeleteSecret(context.Context, *secretsmanager.DeleteSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
}

type connectorSecretsDriver struct{ client secretsManagerAPI }

func (driver *connectorSecretsDriver) Create(ctx context.Context, name, kmsKey string, value []byte) error {
	if driver == nil || driver.client == nil || ctx == nil || len(value) < 1 || len(value) > 2048 {
		return errRuntimeUnavailable
	}
	_, err := driver.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(name), KmsKeyId: aws.String(kmsKey), SecretBinary: append([]byte(nil), value...)})
	if err != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (driver *connectorSecretsDriver) Read(ctx context.Context, name string) ([]byte, error) {
	if driver == nil || driver.client == nil || ctx == nil {
		return nil, errRuntimeUnavailable
	}
	output, err := driver.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(name), VersionStage: aws.String("AWSCURRENT")})
	if err != nil {
		var missing *secretstypes.ResourceNotFoundException
		if errors.As(err, &missing) {
			return nil, apiserver.ErrOAuthSecretNotFound
		}
		return nil, errRuntimeUnavailable
	}
	if output == nil || output.SecretString != nil == (len(output.SecretBinary) > 0) {
		return nil, errRuntimeUnavailable
	}
	if output.SecretString != nil {
		value := []byte(*output.SecretString)
		if len(value) < 1 || len(value) > 2048 {
			return nil, errRuntimeUnavailable
		}
		return value, nil
	}
	if len(output.SecretBinary) < 1 || len(output.SecretBinary) > 2048 {
		return nil, errRuntimeUnavailable
	}
	return append([]byte(nil), output.SecretBinary...), nil
}

func (driver *connectorSecretsDriver) Delete(ctx context.Context, name string) error {
	if driver == nil || driver.client == nil || ctx == nil {
		return errRuntimeUnavailable
	}
	force := true
	_, err := driver.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: aws.String(name), ForceDeleteWithoutRecovery: &force})
	if err != nil {
		return errRuntimeUnavailable
	}
	return nil
}

type assumeRoleWithWebIdentityAPI interface {
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type connectorWebIdentityProvider struct {
	client    assumeRoleWithWebIdentityAPI
	roleARN   string
	tokenFile string
	timeout   time.Duration
}

func (provider *connectorWebIdentityProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if provider == nil || provider.client == nil || ctx == nil || ctx.Err() != nil || !connectorRolePattern.MatchString(provider.roleARN) || provider.tokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	file, err := os.Open(provider.tokenFile)
	if err != nil {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	token, readErr := io.ReadAll(io.LimitReader(file, 16385))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(token) < 64 || len(token) > 16384 || !webIdentityTokenPattern.Match(token) || strings.TrimSpace(string(token)) != string(token) {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	duration := int32(900)
	result, err := provider.client.AssumeRoleWithWebIdentity(bounded, &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(provider.roleARN), RoleSessionName: aws.String("zasp-api-connectors"), WebIdentityToken: aws.String(string(token)), DurationSeconds: &duration})
	clear(token)
	if err != nil || result == nil || result.Credentials == nil || result.Credentials.AccessKeyId == nil || result.Credentials.SecretAccessKey == nil || result.Credentials.SessionToken == nil || result.Credentials.Expiration == nil || !result.Credentials.Expiration.After(time.Now().Add(time.Minute)) {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	return aws.Credentials{AccessKeyID: *result.Credentials.AccessKeyId, SecretAccessKey: *result.Credentials.SecretAccessKey, SessionToken: *result.Credentials.SessionToken, CanExpire: true, Expires: result.Credentials.Expiration.UTC(), Source: "zasp-connector-web-identity"}, nil
}

func newConnectorSecretsClient(config RuntimeConfig) (*secretsmanager.Client, *http.Transport, error) {
	if !validRuntimeConfig(config) {
		return nil, nil, errRuntimeUnavailable
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: config.ProviderTimeout, MaxResponseHeaderBytes: 1 << 20,
	}
	client := &http.Client{Transport: transport, Timeout: config.ProviderTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.ConnectorAWSRegion, HTTPClient: client, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	stsClient := sts.NewFromConfig(base)
	credentials := aws.NewCredentialsCache(&connectorWebIdentityProvider{client: stsClient, roleARN: config.ConnectorRoleARN, tokenFile: config.ConnectorTokenFile, timeout: config.ProviderTimeout})
	base.Credentials = credentials
	return secretsmanager.NewFromConfig(base), transport, nil
}

var _ apiserver.OAuthSecretDriver = (*connectorSecretsDriver)(nil)
var _ aws.CredentialsProvider = (*connectorWebIdentityProvider)(nil)
