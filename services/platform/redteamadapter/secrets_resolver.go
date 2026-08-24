package redteamadapter

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SecretsAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type SecretsCredentialResolver struct {
	client  SecretsAPI
	prefix  string
	timeout time.Duration
}

func NewSecretsCredentialResolver(client SecretsAPI, prefix string, timeout time.Duration) (*SecretsCredentialResolver, error) {
	if client == nil || prefix != "zasp/red-team/targets" || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrAdapter
	}
	return &SecretsCredentialResolver{client: client, prefix: prefix, timeout: timeout}, nil
}

func (resolver *SecretsCredentialResolver) ResolveTargetCredential(ctx context.Context, reference string) (*Credential, error) {
	if resolver == nil || resolver.client == nil || ctx == nil || ctx.Err() != nil || !credentialReferenceRE.MatchString(reference) {
		return nil, ErrAdapter
	}
	identifier := strings.TrimPrefix(reference, "ref:red-team/")
	if identifier == reference || identifier == "" {
		return nil, ErrAdapter
	}
	bounded, cancel := context.WithTimeout(ctx, resolver.timeout)
	defer cancel()
	stage := "AWSCURRENT"
	output, err := resolver.client.GetSecretValue(bounded, &secretsmanager.GetSecretValueInput{SecretId: aws.String(resolver.prefix + "/" + identifier), VersionStage: &stage}, func(options *secretsmanager.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || bounded.Err() != nil || output == nil || output.SecretString != nil || len(output.SecretBinary) < 32 || len(output.SecretBinary) > 4096 {
		if output != nil {
			clear(output.SecretBinary)
		}
		return nil, ErrAdapter
	}
	secret := append([]byte(nil), output.SecretBinary...)
	clear(output.SecretBinary)
	output.SecretBinary = nil
	credential, credentialErr := newCredential(secret, func() {})
	if credentialErr != nil {
		clear(secret)
		return nil, ErrAdapter
	}
	return credential, nil
}

var _ CredentialResolver = (*SecretsCredentialResolver)(nil)
