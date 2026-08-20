package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type discoverySecretsManagerStub struct {
	input  *secretsmanager.GetSecretValueInput
	output *secretsmanager.GetSecretValueOutput
	err    error
}

func (stub *discoverySecretsManagerStub) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, options ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	stub.input = input
	for _, option := range options {
		option(&secretsmanager.Options{})
	}
	return stub.output, stub.err
}

func TestDiscoverySecretsManagerReaderUsesExactAWSCURRENTName(t *testing.T) {
	stub := &discoverySecretsManagerStub{output: &secretsmanager.GetSecretValueOutput{SecretBinary: []byte("external-id-customer-0001")}}
	reader, err := newDiscoverySecretsManagerReader(stub, "zasp/connectors", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	value, err := reader.ResolveDiscoverySecret(context.Background(), "ref:aws/external-id/customer-0001")
	if err != nil || !bytes.Equal(value, []byte("external-id-customer-0001")) || aws.ToString(stub.input.SecretId) != "zasp/connectors/aws/external-id/customer-0001" || aws.ToString(stub.input.VersionStage) != "AWSCURRENT" {
		t.Fatalf("value=%q input=%#v err=%v", value, stub.input, err)
	}
	clear(value)
	for _, reference := range []string{"ref:aws/../secret", "ref:other/value-0001", "secret", "ref:okta/refresh/with space"} {
		stub.input = nil
		if _, err := reader.ResolveDiscoverySecret(context.Background(), reference); err == nil || stub.input != nil {
			t.Fatalf("hostile reference %q reached Secrets Manager", reference)
		}
	}
}

func TestProductionDiscoveryCloudAuthorityHasNoAmbientCredentialsOrProxy(t *testing.T) {
	now := time.Now().UTC()
	authority, err := newProductionDiscoveryCloudAuthority(productionDiscoveryCloudConfig{Region: "us-east-1", RoleARN: "arn:aws:iam::123456789012:role/zasp-discovery-worker", TokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", SecretRoot: "zasp/connectors", Timeout: time.Second, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if authority.base.Region != "us-east-1" || authority.base.Credentials != authority.credentials || authority.transport.Proxy != nil || authority.secrets == nil || authority.assumeRole == nil || authority.s3 == nil {
		t.Fatalf("authority=%#v", authority)
	}
	for _, mutate := range []func(*productionDiscoveryCloudConfig){
		func(config *productionDiscoveryCloudConfig) { config.RoleARN = "" },
		func(config *productionDiscoveryCloudConfig) { config.TokenFile = "/tmp/token" },
		func(config *productionDiscoveryCloudConfig) { config.SecretRoot = "zasp/connectors/oauth" },
		func(config *productionDiscoveryCloudConfig) { config.Timeout = 31 * time.Second },
		func(config *productionDiscoveryCloudConfig) { config.Clock = nil },
	} {
		config := productionDiscoveryCloudConfig{Region: "us-east-1", RoleARN: "arn:aws:iam::123456789012:role/zasp-discovery-worker", TokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", SecretRoot: "zasp/connectors", Timeout: time.Second, Clock: func() time.Time { return now }}
		mutate(&config)
		if _, err := newProductionDiscoveryCloudAuthority(config); err == nil {
			t.Fatal("hostile cloud authority accepted")
		}
	}
}

func TestDiscoveryWebIdentityProviderRejectsUntrustedTokenWithoutSTS(t *testing.T) {
	provider := &discoveryWebIdentityProvider{client: &discoveryWebIdentityStub{}, roleARN: "arn:aws:iam::123456789012:role/zasp-discovery-worker", tokenFile: "/tmp/not-projected", timeout: time.Second, clock: func() time.Time { return time.Now().UTC() }}
	if _, err := provider.Retrieve(context.Background()); err == nil || !strings.Contains(err.Error(), "runtime") {
		t.Fatalf("untrusted path err=%v", err)
	}
}

type discoveryWebIdentityStub struct {
	input *sts.AssumeRoleWithWebIdentityInput
}

func (stub *discoveryWebIdentityStub) AssumeRoleWithWebIdentity(_ context.Context, input *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	stub.input = input
	return &sts.AssumeRoleWithWebIdentityOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE000001"), SecretAccessKey: aws.String(strings.Repeat("s", 40)), SessionToken: aws.String(strings.Repeat("t", 64)), Expiration: aws.Time(time.Now().UTC().Add(15 * time.Minute))}}, nil
}

var _ discoverySecretsManagerAPI = (*discoverySecretsManagerStub)(nil)
var _ discoveryWebIdentityAPI = (*discoveryWebIdentityStub)(nil)
