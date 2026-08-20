package main

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type discoveryArtifactReadinessStub struct {
	head       *s3.HeadBucketOutput
	versioning *s3.GetBucketVersioningOutput
	encryption *s3.GetBucketEncryptionOutput
	key        *kms.DescribeKeyOutput
	identity   *sts.GetCallerIdentityOutput
}

func (stub *discoveryArtifactReadinessStub) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return stub.head, nil
}
func (stub *discoveryArtifactReadinessStub) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return stub.versioning, nil
}
func (stub *discoveryArtifactReadinessStub) GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return stub.encryption, nil
}
func (stub *discoveryArtifactReadinessStub) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return stub.key, nil
}
func (stub *discoveryArtifactReadinessStub) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return stub.identity, nil
}

func TestProductionDiscoveryDependenciesComposeExplicitAuthorities(t *testing.T) {
	now := time.Now().UTC()
	config := validProductionDiscoveryDependencyConfig(now)
	dependencies, err := newProductionDiscoveryDependencies(config)
	if err != nil {
		t.Fatal(err)
	}
	if dependencies.Factory == nil || dependencies.Queue == nil || dependencies.ready == nil || dependencies.close == nil {
		t.Fatalf("dependencies=%#v", dependencies)
	}
	if err := dependencies.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProductionDiscoveryDependenciesRejectCrossAuthorityAndAmbientConfig(t *testing.T) {
	now := time.Now().UTC()
	mutations := []func(*productionDiscoveryDependencyConfig){
		func(config *productionDiscoveryDependencyConfig) { config.Cloud.Region = "us-west-2" },
		func(config *productionDiscoveryDependencyConfig) {
			config.Cloud.RoleARN = "arn:aws:iam::999999999999:role/zasp-discovery-worker"
		},
		func(config *productionDiscoveryDependencyConfig) { config.Cloud.SecretRoot = "zasp/connectors/oauth" },
		func(config *productionDiscoveryDependencyConfig) {
			config.GitHubPrivateKeyReference = "ref:okta/app-private-key-0001"
		},
		func(config *productionDiscoveryDependencyConfig) {
			config.OktaClientSecretReference = "ref:github/client-secret-0001"
		},
		func(config *productionDiscoveryDependencyConfig) {
			config.KubernetesAllowedCIDRs = []string{"0.0.0.0/0"}
		},
		func(config *productionDiscoveryDependencyConfig) { config.ProviderTimeout = 0 },
	}
	for index, mutate := range mutations {
		config := validProductionDiscoveryDependencyConfig(now)
		mutate(&config)
		dependencies, err := newProductionDiscoveryDependencies(config)
		if err == nil || dependencies != nil {
			if dependencies != nil {
				_ = dependencies.Close()
			}
			t.Fatalf("hostile config %d accepted", index)
		}
	}
}

func TestProductionDiscoveryDependenciesReadinessRejectsInvalidContextWithoutIO(t *testing.T) {
	dependencies, err := newProductionDiscoveryDependencies(validProductionDiscoveryDependencyConfig(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	defer dependencies.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dependencies.Ready(ctx); err == nil {
		t.Fatal("canceled readiness accepted")
	}
}

func TestProductionDiscoveryReadinessAttestsRoleVersionedEncryptedArtifactAuthority(t *testing.T) {
	config := validProductionDiscoveryDependencyConfig(time.Now().UTC())
	keyID := "11111111-1111-4111-8111-111111111111"
	stub := &discoveryArtifactReadinessStub{
		head:       &s3.HeadBucketOutput{BucketRegion: aws.String("us-east-1")},
		versioning: &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled},
		encryption: &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String(config.Artifacts.KMSKeyARN)}, BucketKeyEnabled: aws.Bool(true)}}}},
		key:        &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{AWSAccountId: aws.String("123456789012"), Arn: aws.String(config.Artifacts.KMSKeyARN), KeyId: aws.String(keyID), Enabled: true, KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, KeySpec: kmstypes.KeySpecSymmetricDefault, Origin: kmstypes.OriginTypeAwsKms}},
		identity:   &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/zasp-discovery-worker/zasp-discovery-worker")},
	}
	if err := readyProductionDiscoveryRole(context.Background(), stub, config.Cloud, config.Artifacts); err != nil {
		t.Fatal(err)
	}
	if err := readyProductionDiscoveryArtifactAuthority(context.Background(), stub, stub, config.Cloud, config.Artifacts); err != nil {
		t.Fatal(err)
	}
	stub.versioning.Status = s3types.BucketVersioningStatusSuspended
	if err := readyProductionDiscoveryArtifactAuthority(context.Background(), stub, stub, config.Cloud, config.Artifacts); err == nil {
		t.Fatal("suspended versioning accepted")
	}
	stub.versioning.Status = s3types.BucketVersioningStatusEnabled
	stub.encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID = aws.String("arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222")
	if err := readyProductionDiscoveryArtifactAuthority(context.Background(), stub, stub, config.Cloud, config.Artifacts); err == nil {
		t.Fatal("foreign KMS default accepted")
	}
}

func validProductionDiscoveryDependencyConfig(now time.Time) productionDiscoveryDependencyConfig {
	return productionDiscoveryDependencyConfig{
		Cloud: productionDiscoveryCloudConfig{
			Region: "us-east-1", RoleARN: "arn:aws:iam::123456789012:role/zasp-discovery-worker",
			TokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", SecretRoot: "zasp/connectors", Timeout: time.Second, Clock: func() time.Time { return now },
		},
		Artifacts: productionDiscoveryArtifactConfig{
			Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012",
			KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20,
		},
		GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001",
		OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001",
		AWSCollectorVersion: "collector_v1", KubernetesCollectorVersion: "kubernetes_v1", GitHubCollectorVersion: "github_v1", OktaCollectorVersion: "okta_v1",
		ParserVersion: "parser_v1", ToolVersion: "tool_v1",
		KubernetesAllowedCIDRs: []string{"203.0.113.0/24"}, ProviderTimeout: time.Second, ReadinessTimeout: time.Second,
		QueueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-discovery-jobs", QueueOperationTimeout: time.Second, LeaseDuration: 30 * time.Second, ShutdownTimeout: 15 * time.Second,
	}
}
