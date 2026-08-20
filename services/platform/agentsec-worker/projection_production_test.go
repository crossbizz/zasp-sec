package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestProjectionWebIdentityProviderUsesOnlyExactProjectedToken(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(tokenPath, []byte(token), 0o400); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(15 * time.Minute)
	api := &projectionSTSStub{output: &sts.AssumeRoleWithWebIdentityOutput{Credentials: &types.Credentials{
		AccessKeyId: aws.String("AKIAEXAMPLE00000000"), SecretAccessKey: aws.String("secret-material"), SessionToken: aws.String("session-material"), Expiration: &expires,
	}}}
	provider := &projectionWebIdentityProvider{client: api, roleARN: "arn:aws:iam::123456789012:role/zasp-production-projection-search", tokenFile: tokenPath, timeout: time.Second}
	credentials, err := provider.Retrieve(context.Background())
	if err != nil || credentials.AccessKeyID != "AKIAEXAMPLE00000000" || credentials.Source != "zasp-projection-web-identity" {
		t.Fatalf("Retrieve() = %#v, %v", credentials, err)
	}
	if api.input == nil || aws.ToString(api.input.RoleArn) != provider.roleARN || aws.ToString(api.input.WebIdentityToken) != token || aws.ToString(api.input.RoleSessionName) != "zasp-projection-worker" {
		t.Fatalf("STS input = %#v", api.input)
	}

	provider.tokenFile = filepath.Join(directory, "missing")
	if value, err := provider.Retrieve(context.Background()); !errors.Is(err, errRuntimeUnavailable) || value != (aws.Credentials{}) {
		t.Fatalf("ambient fallback = %#v, %v", value, err)
	}
}

func TestNeo4jSecretsResolverMapsOpaqueReferenceAndRejectsMalformedSecret(t *testing.T) {
	t.Parallel()
	secret := `{"scheme":"basic","principal":"neo4j","credentials":"password-material"}`
	api := &projectionSecretsStub{output: &secretsmanager.GetSecretValueOutput{SecretString: &secret}}
	resolver := &projectionNeo4jAuthenticationResolver{client: api, prefix: "zasp-production/projection"}
	manager, err := resolver.ResolveNeo4jAuthentication(context.Background(), "ref:neo4j/auth/production")
	if err != nil || manager == nil {
		t.Fatalf("ResolveNeo4jAuthentication() = %#v, %v", manager, err)
	}
	if api.secretID != "zasp-production/projection/neo4j/auth/production" {
		t.Fatalf("secret id = %q", api.secretID)
	}
	token, err := manager.GetAuthToken(context.Background())
	if err != nil || token.Tokens["scheme"] != "basic" || token.Tokens["principal"] != "neo4j" || token.Tokens["credentials"] != "password-material" {
		t.Fatalf("resolved token = %#v, %v", token, err)
	}

	malformed := `{"scheme":"basic","principal":"neo4j","credentials":"password-material","access_token":"escape"}`
	api.output = &secretsmanager.GetSecretValueOutput{SecretString: &malformed}
	if manager, err := resolver.ResolveNeo4jAuthentication(context.Background(), "ref:neo4j/auth/production"); !errors.Is(err, errRuntimeUnavailable) || manager != nil {
		t.Fatalf("malformed secret = %#v, %v", manager, err)
	}
	if manager, err := resolver.ResolveNeo4jAuthentication(context.Background(), "ref:neo4j/production"); !errors.Is(err, errRuntimeUnavailable) || manager != nil {
		t.Fatalf("legacy ambiguous reference = %#v, %v", manager, err)
	}
}

func TestProjectionCallerIdentityBindsExactConfiguredRole(t *testing.T) {
	t.Parallel()
	api := &projectionIdentityStub{output: &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/zasp-production-projection-search/zasp-projection-worker"), UserId: aws.String("AROATEST:zasp-projection-worker"),
	}}
	roleARN := "arn:aws:iam::123456789012:role/zasp-production-projection-search"
	if err := verifyProjectionCallerIdentity(context.Background(), api, roleARN); err != nil || api.calls != 1 {
		t.Fatalf("verifyProjectionCallerIdentity() error=%v calls=%d", err, api.calls)
	}
	for _, output := range []*sts.GetCallerIdentityOutput{
		{Account: aws.String("210987654321"), Arn: aws.String("arn:aws:sts::210987654321:assumed-role/zasp-production-projection-search/zasp-projection-worker"), UserId: aws.String("AROATEST:zasp-projection-worker")},
		{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/other-role/zasp-projection-worker"), UserId: aws.String("AROATEST:zasp-projection-worker")},
		{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:iam::123456789012:role/zasp-production-projection-search"), UserId: aws.String("AROATEST")},
	} {
		api.output = output
		if err := verifyProjectionCallerIdentity(context.Background(), api, roleARN); !errors.Is(err, errRuntimeUnavailable) || strings.Contains(err.Error(), "other-role") {
			t.Fatalf("hostile identity %#v error = %v", output, err)
		}
	}
}

type projectionSTSStub struct {
	input  *sts.AssumeRoleWithWebIdentityInput
	output *sts.AssumeRoleWithWebIdentityOutput
	err    error
}

func (stub *projectionSTSStub) AssumeRoleWithWebIdentity(_ context.Context, input *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	stub.input = input
	return stub.output, stub.err
}

type projectionSecretsStub struct {
	secretID string
	output   *secretsmanager.GetSecretValueOutput
	err      error
}

type projectionIdentityStub struct {
	calls  int
	output *sts.GetCallerIdentityOutput
	err    error
}

func (stub *projectionIdentityStub) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	stub.calls++
	return stub.output, stub.err
}

func (stub *projectionSecretsStub) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	stub.secretID = aws.ToString(input.SecretId)
	return stub.output, stub.err
}
