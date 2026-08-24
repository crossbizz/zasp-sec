package redteamadapter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type secretsAPIStub struct {
	input  *secretsmanager.GetSecretValueInput
	output *secretsmanager.GetSecretValueOutput
	err    error
}

func (stub *secretsAPIStub) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, options ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	stub.input = input
	configured := secretsmanager.Options{}
	for _, option := range options {
		option(&configured)
	}
	if configured.Retryer == nil {
		return nil, errors.New("retryer missing")
	}
	return stub.output, stub.err
}

func TestSecretsCredentialResolverLoadsExactBinarySecretAndZeroizesEveryCopy(t *testing.T) {
	providerCopy := []byte(strings.Repeat("s", 64))
	stub := &secretsAPIStub{output: &secretsmanager.GetSecretValueOutput{SecretBinary: providerCopy}}
	resolver, err := NewSecretsCredentialResolver(stub, "zasp/red-team/targets", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := resolver.ResolveTargetCredential(context.Background(), "ref:red-team/target-0001")
	if err != nil || credential == nil || stub.input == nil || *stub.input.SecretId != "zasp/red-team/targets/target-0001" || *stub.input.VersionStage != "AWSCURRENT" {
		t.Fatalf("credential=%v input=%#v err=%v", credential, stub.input, err)
	}
	for _, value := range providerCopy {
		if value != 0 {
			t.Fatal("provider secret copy was retained")
		}
	}
	secret, ok := credential.bytes()
	if !ok || string(secret) != strings.Repeat("s", 64) {
		t.Fatal("credential payload unavailable")
	}
	clear(secret)
	credential.Destroy()
	if secret, ok := credential.bytes(); ok || secret != nil {
		t.Fatal("destroyed credential remained readable")
	}
}

func TestSecretsCredentialResolverRejectsReferenceProviderAndSecretShapeWithoutLeakage(t *testing.T) {
	secretString := strings.Repeat("x", 64)
	for name, input := range map[string]struct {
		reference string
		output    *secretsmanager.GetSecretValueOutput
		err       error
	}{
		"foreign reference": {reference: "ref:github/installation/1", output: &secretsmanager.GetSecretValueOutput{SecretBinary: []byte(strings.Repeat("s", 64))}},
		"string secret":     {reference: "ref:red-team/target-0001", output: &secretsmanager.GetSecretValueOutput{SecretString: &secretString}},
		"short binary":      {reference: "ref:red-team/target-0001", output: &secretsmanager.GetSecretValueOutput{SecretBinary: []byte("short")}},
		"provider error":    {reference: "ref:red-team/target-0001", err: errors.New("provider-secret-value")},
	} {
		t.Run(name, func(t *testing.T) {
			resolver, err := NewSecretsCredentialResolver(&secretsAPIStub{output: input.output, err: input.err}, "zasp/red-team/targets", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			credential, resolveErr := resolver.ResolveTargetCredential(context.Background(), input.reference)
			if credential != nil || !errors.Is(resolveErr, ErrAdapter) || strings.Contains(resolveErr.Error(), "provider-secret-value") {
				t.Fatalf("credential=%v error=%v", credential, resolveErr)
			}
		})
	}
}
