package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
)

type referenceAssumeRoleStub struct {
	input      *sts.AssumeRoleInput
	roleARN    string
	externalID string
	duration   int32
	err        error
}

func (stub *referenceAssumeRoleStub) AssumeRole(_ context.Context, input *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	stub.input = input
	stub.roleARN = aws.ToString(input.RoleArn)
	stub.externalID = aws.ToString(input.ExternalId)
	stub.duration = aws.ToInt32(input.DurationSeconds)
	if stub.err != nil {
		return nil, stub.err
	}
	expires := time.Now().Add(10 * time.Minute)
	return &sts.AssumeRoleOutput{Credentials: &types.Credentials{AccessKeyId: aws.String("AKIAREFERENCE"), SecretAccessKey: aws.String("secret-reference"), SessionToken: aws.String("session-reference"), Expiration: &expires}}, nil
}

type referenceCallerIdentityStub struct {
	output *sts.GetCallerIdentityOutput
	err    error
}

func (stub *referenceCallerIdentityStub) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return stub.output, stub.err
}

func TestReferenceSecretResolverMapsOnlyCanonicalNamespaces(t *testing.T) {
	secrets := &connectorSecretsAPIStub{values: map[string][]byte{
		"zasp/aws/external-id/customer-0001":       []byte("external-id-value"),
		"zasp/kubernetes/connection/customer-0001": []byte(`{"endpoint":"https://cluster.example.test"}`),
		"zasp/kubernetes/ca/customer-0001":         []byte("certificate"),
		"zasp/kubernetes/credential/customer-0001": []byte("credential"),
	}}
	resolver := &referenceSecretResolver{driver: &connectorSecretsDriver{client: secrets}, root: "zasp"}
	for reference, want := range map[string]string{
		"ref:aws/external-id/customer-0001":       "external-id-value",
		"ref:kubernetes/connection/customer-0001": `{"endpoint":"https://cluster.example.test"}`,
		"ref:kubernetes/ca/customer-0001":         "certificate",
		"ref:kubernetes/credential/customer-0001": "credential",
	} {
		value, err := resolver.Resolve(context.Background(), reference)
		if err != nil || string(value) != want {
			t.Fatalf("resolve %q = %q, %v", reference, value, err)
		}
	}
	for _, reference := range []string{"ref:aws/external-id/../customer", "ref:aws/external-id/customer?version=1", "ref:kubernetes/credential/customer/child", "ref:github/token/customer-0001", "ref:aws/external-id/short"} {
		if _, err := resolver.Resolve(context.Background(), reference); !errors.Is(err, errRuntimeUnavailable) {
			t.Fatalf("hostile reference %q = %v", reference, err)
		}
	}
}

func TestAWSReferenceIdentityUsesOnlyExplicitScopedAssumeRoleCredentials(t *testing.T) {
	assume := &referenceAssumeRoleStub{}
	caller := &referenceCallerIdentityStub{output: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/zasp/customer")}}
	var region string
	var credentials aws.Credentials
	client := &awsReferenceIdentityClient{assume: assume, rolePrefix: "arn:aws:iam::123456789012:role/zasp/", newCaller: func(value string, valueCredentials aws.Credentials) awsCallerIdentityAPI {
		region, credentials = value, valueCredentials
		return caller
	}}
	request := awsdiscovery.AssumeRoleRequest{RoleARN: "arn:aws:iam::123456789012:role/zasp/customer", Region: "us-east-1", ExternalID: []byte("external-id-value"), Duration: 15 * time.Minute}
	identity, err := client.GetCallerIdentity(context.Background(), request)
	if err != nil || identity.AccountID != "123456789012" || assume.input == nil || assume.roleARN != request.RoleARN || assume.externalID != "external-id-value" || assume.duration != 900 || region != request.Region || credentials.AccessKeyID == "" || !credentials.CanExpire {
		t.Fatalf("identity=%#v err=%v assume=%#v region=%q credentials=%#v", identity, err, assume.input, region, credentials)
	}
	assume.input = nil
	request.RoleARN = "arn:aws:iam::123456789012:role/unscoped/customer"
	if _, err := client.GetCallerIdentity(context.Background(), request); !errors.Is(err, errRuntimeUnavailable) || assume.input != nil {
		t.Fatalf("unscoped role reached STS: err=%v input=%#v", err, assume.input)
	}
}

type referenceIdentityClientStub struct{}

func (*referenceIdentityClientStub) GetCallerIdentity(context.Context, awsdiscovery.AssumeRoleRequest) (awsdiscovery.Identity, error) {
	return awsdiscovery.Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/zasp/customer"}, nil
}

type referenceKubernetesProbeStub struct{}

func (*referenceKubernetesProbeStub) Probe(context.Context, kubernetesdiscovery.ProbeRequest) (kubernetesdiscovery.ProbeResult, error) {
	return kubernetesdiscovery.ProbeResult{ClusterID: "cluster.example.test/customer", ServerVersion: "v1.30.1", AllowedVerbs: []string{"api-discovery", "get", "list", "watch"}}, nil
}

func TestReferenceProviderConfigurationDecodersRejectTrailingDocuments(t *testing.T) {
	secretAPI := &connectorSecretsAPIStub{values: map[string][]byte{
		"zasp/aws/external-id/customer-0001":       []byte("external-id-value"),
		"zasp/kubernetes/connection/customer-0001": []byte(`{"endpoint":"https://cluster.example.test","context":"customer","ca_reference":"ref:kubernetes/ca/customer-0001","credential_reference":"ref:kubernetes/credential/customer-0001"} {}`),
	}}
	resolver := &referenceSecretResolver{driver: &connectorSecretsDriver{client: secretAPI}, root: "zasp"}
	awsAdapter, _ := awsdiscovery.NewAdapter(&referenceIdentityClientStub{}, resolver, time.Second)
	awsProbe := &awsReferenceProbe{adapter: awsAdapter}
	awsConfiguration := json.RawMessage(`{"role_arn":"arn:aws:iam::123456789012:role/zasp/customer","external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1"} {}`)
	if err := awsProbe.ProbeReferenceAuthorization(context.Background(), apiserver.ReferenceAuthorizationTarget{Provider: "aws", Configuration: awsConfiguration}); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("AWS trailing document = %v", err)
	}
	kubernetesAdapter, _ := kubernetesdiscovery.NewAdapter(&referenceKubernetesProbeStub{}, time.Second)
	kubernetesProbe := &kubernetesReferenceProbe{adapter: kubernetesAdapter, resolver: resolver}
	kubernetesConfiguration := json.RawMessage(`{"connection_reference":"ref:kubernetes/connection/customer-0001"}`)
	if err := kubernetesProbe.ProbeReferenceAuthorization(context.Background(), apiserver.ReferenceAuthorizationTarget{Provider: "kubernetes", ConnectionReference: "ref:kubernetes/connection/customer-0001", Configuration: kubernetesConfiguration}); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("Kubernetes trailing descriptor = %v", err)
	}
}

func TestKubernetesReferenceProbeRejectsAnyDNSAddressOutsideConfiguredCIDRsBeforeSecrets(t *testing.T) {
	_, allowed, _ := net.ParseCIDR("203.0.113.0/24")
	client := &kubernetesProbeClient{
		resolver: &referenceSecretResolver{driver: &connectorSecretsDriver{client: &connectorSecretsAPIStub{}}, root: "zasp"},
		cidrs:    []*net.IPNet{allowed},
		lookup: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}, {IP: net.ParseIP("127.0.0.1")}}, nil
		},
		timeout: time.Second,
	}
	_, err := client.Probe(context.Background(), kubernetesdiscovery.ProbeRequest{Endpoint: "https://cluster.example.test", CAReference: "ref:kubernetes/ca/customer-0001", CredentialReference: "ref:kubernetes/credential/customer-0001", Context: "customer"})
	if !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("mixed DNS answer accepted: %v", err)
	}
}
