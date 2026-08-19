package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type connectorSecretsAPIStub struct {
	created *secretsmanager.CreateSecretInput
	value   *secretsmanager.GetSecretValueOutput
}

func (stub *connectorSecretsAPIStub) CreateSecret(_ context.Context, input *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	stub.created = input
	return &secretsmanager.CreateSecretOutput{}, nil
}
func (stub *connectorSecretsAPIStub) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return stub.value, nil
}
func (*connectorSecretsAPIStub) DeleteSecret(context.Context, *secretsmanager.DeleteSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	return &secretsmanager.DeleteSecretOutput{}, nil
}

func TestConnectorSecretsDriverUsesKMSAndAcceptsOneBoundedAWSRepresentation(t *testing.T) {
	stub := &connectorSecretsAPIStub{}
	driver := &connectorSecretsDriver{client: stub}
	value := []byte("provider-secret-value")
	if err := driver.Create(context.Background(), "zasp/github/app", "arn:aws:kms:us-east-1:000000000000:key/11111111-1111-4111-8111-111111111111", value); err != nil {
		t.Fatal(err)
	}
	if stub.created == nil || aws.ToString(stub.created.Name) != "zasp/github/app" || aws.ToString(stub.created.KmsKeyId) == "" || string(stub.created.SecretBinary) != string(value) || stub.created.SecretString != nil {
		t.Fatalf("create input = %#v", stub.created)
	}
	secretString := "provider-secret-value"
	stub.value = &secretsmanager.GetSecretValueOutput{SecretString: &secretString}
	read, err := driver.Read(context.Background(), "zasp/github/app")
	if err != nil || string(read) != secretString {
		t.Fatalf("secret string read = %q, %v", read, err)
	}
	stub.value = &secretsmanager.GetSecretValueOutput{SecretBinary: value, SecretString: &secretString}
	if _, err := driver.Read(context.Background(), "zasp/github/app"); err == nil {
		t.Fatal("ambiguous secret representations accepted")
	}
}

func TestConnectorProviderHTTPClientDisablesAmbientProxyRedirectsAndLegacyTLS(t *testing.T) {
	client, err := newConnectorHTTPClient(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("provider transport = %#v", client.Transport)
	}
	request, _ := http.NewRequest("GET", "https://example.test", nil)
	if err := client.CheckRedirect(request, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v", err)
	}
}
