package redteamadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	if err != nil || bounded.Err() != nil || output == nil || output.SecretString != nil || len(output.SecretBinary) < 32 || len(output.SecretBinary) > 4096 || output.VersionId == nil || !validSecretVersion(*output.VersionId) {
		if output != nil {
			clear(output.SecretBinary)
			output.SecretBinary = nil
		}
		return nil, ErrAdapter
	}
	// VersionId and secret bytes come from the same GetSecretValue response.
	// Include the reference so equal version labels on distinct secrets differ.
	versionDigest := sha256.Sum256([]byte("zasp-red-team-credential-version-v1\x00" + reference + "\x00" + *output.VersionId))
	secret := append([]byte(nil), output.SecretBinary...)
	clear(output.SecretBinary)
	output.SecretBinary = nil
	credential, credentialErr := newCredential(secret, func() {})
	if credentialErr != nil {
		clear(secret)
		return nil, ErrAdapter
	}
	credential.versionDigest = hex.EncodeToString(versionDigest[:])
	return credential, nil
}

func validSecretVersion(value string) bool {
	if len(value) < 32 || len(value) > 64 {
		return false
	}
	for _, b := range []byte(value) {
		if b <= 0x20 || b >= 0x7f {
			return false
		}
	}
	return true
}

var _ CredentialResolver = (*SecretsCredentialResolver)(nil)
