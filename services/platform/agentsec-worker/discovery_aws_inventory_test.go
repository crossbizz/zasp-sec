package main

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
)

type discoveryInventoryIAMStub struct{}

func (*discoveryInventoryIAMStub) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	trust := url.QueryEscape(`{"Statement":[],"Version":"2012-10-17"}`)
	created := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{{Arn: aws.String("arn:aws:iam::123456789012:role/reader"), AssumeRolePolicyDocument: &trust, CreateDate: &created, Path: aws.String("/"), RoleId: aws.String("AROA1234567890ABCDEF"), RoleName: aws.String("reader")}}}, nil
}

func (*discoveryInventoryIAMStub) ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{{PolicyArn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess"), PolicyName: aws.String("ReadOnlyAccess")}}}, nil
}

func (*discoveryInventoryIAMStub) GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{Arn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess"), DefaultVersionId: aws.String("v1"), PolicyName: aws.String("ReadOnlyAccess")}}, nil
}

func (*discoveryInventoryIAMStub) GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	document := url.QueryEscape(`{"Statement":[{"Action":["ec2:DescribeInstances"],"Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}`)
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: &document, VersionId: aws.String("v1")}}, nil
}

type discoveryInventoryEC2Stub struct{ region string }

func (stub *discoveryInventoryEC2Stub) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	return &ec2.DescribeRegionsOutput{Regions: []ec2types.Region{{RegionName: aws.String("us-east-1"), OptInStatus: aws.String("opt-in-not-required")}, {RegionName: aws.String("us-west-2"), OptInStatus: aws.String("opted-in")}}}, nil
}

func (stub *discoveryInventoryEC2Stub) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if stub.region != "us-east-1" {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{
		{Instances: []ec2types.Instance{
			{InstanceId: aws.String("i-0123456789abcdef0"), MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled, HttpTokens: ec2types.HttpTokensStateRequired}, State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}},
		}},
	}}, nil
}

func TestAWSInventoryCallerBuildsCanonicalMultiRegionSecuritySources(t *testing.T) {
	t.Parallel()
	clock := func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }
	caller, err := newDiscoveryAWSCollectionInventoryCaller(discoveryAWSInventoryFactory{
		Identity: func(string, aws.Credentials) (discoveryCallerIdentityAPI, error) {
			return &discoveryCallerIdentityStub{output: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/zasp/session")}}, nil
		},
		IAM: func(string, aws.Credentials) (discoveryAWSIAMAPI, error) { return &discoveryInventoryIAMStub{}, nil },
		EC2: func(region string, _ aws.Credentials) (discoveryAWSEC2API, error) {
			return &discoveryInventoryEC2Stub{region: region}, nil
		},
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	credential := mustDiscoveryAWSCredentialEnvelope(t, clock().Add(15*time.Minute))
	inventory, err := caller.GetCollectionInventory(context.Background(), credential)
	clear(credential)
	if err != nil || inventory.Identity.AccountID != "123456789012" || inventory.CredentialExpiresAt != clock().Add(15*time.Minute) {
		t.Fatalf("inventory authority = %#v, %v", inventory, err)
	}
	var cartography struct {
		AccountID string                      `json:"account_id"`
		Policies  map[string]map[string][]any `json:"managed_policies"`
		Roles     []json.RawMessage           `json:"roles"`
	}
	var prowler struct {
		AccountID string            `json:"account_id"`
		Instances []json.RawMessage `json:"instances"`
		Roles     []json.RawMessage `json:"roles"`
	}
	if json.Unmarshal(inventory.CartographySource, &cartography) != nil || json.Unmarshal(inventory.ProwlerSource, &prowler) != nil || cartography.AccountID != "123456789012" || prowler.AccountID != "123456789012" || len(cartography.Roles) != 1 || len(cartography.Policies) != 1 || len(prowler.Roles) != 1 || len(prowler.Instances) != 1 {
		t.Fatalf("canonical sources = %s / %s", inventory.CartographySource, inventory.ProwlerSource)
	}
}

func mustDiscoveryAWSCredentialEnvelope(t *testing.T, expiresAt time.Time) []byte {
	t.Helper()
	encoded, err := encodeDiscoveryCredentialEnvelope(discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: "aws", SubjectKind: "aws_account", SubjectID: "123456789012", ExpiresAt: expiresAt.UTC(), Region: "us-east-1", AccessKeyID: []byte("ASIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), SessionToken: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

var _ awsdiscovery.CollectionInventoryCaller = (*discoveryAWSCollectionInventoryCaller)(nil)
