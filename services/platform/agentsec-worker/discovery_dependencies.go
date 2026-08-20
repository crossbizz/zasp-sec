package main

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type productionDiscoveryDependencyConfig struct {
	Cloud                      productionDiscoveryCloudConfig
	Artifacts                  productionDiscoveryArtifactConfig
	GitHubAppID                string
	GitHubPrivateKeyReference  string
	OktaClientID               string
	OktaClientSecretReference  string
	AWSCollectorVersion        string
	KubernetesCollectorVersion string
	GitHubCollectorVersion     string
	OktaCollectorVersion       string
	ParserVersion              string
	ToolVersion                string
	KubernetesAllowedCIDRs     []string
	ProviderTimeout            time.Duration
	ReadinessTimeout           time.Duration
	QueueURL                   string
	QueueOperationTimeout      time.Duration
	LeaseDuration              time.Duration
	ShutdownTimeout            time.Duration
}

type discoveryArtifactReadinessAPI interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
}

type discoveryKMSReadinessAPI interface {
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

type discoveryRoleReadinessAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func readyProductionDiscoveryArtifactAuthority(ctx context.Context, s3API discoveryArtifactReadinessAPI, kmsAPI discoveryKMSReadinessAPI, cloud productionDiscoveryCloudConfig, artifacts productionDiscoveryArtifactConfig) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(s3API) || nilWorkerDependency(kmsAPI) || !validProductionDiscoveryCloudConfig(cloud) {
		return errRuntimeUnavailable
	}
	head, err := s3API.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(artifacts.Bucket), ExpectedBucketOwner: aws.String(artifacts.ExpectedBucketOwner)}, func(options *s3.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || ctx.Err() != nil || head == nil || aws.ToString(head.BucketRegion) != cloud.Region {
		return errRuntimeUnavailable
	}
	versioning, err := s3API.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(artifacts.Bucket), ExpectedBucketOwner: aws.String(artifacts.ExpectedBucketOwner)}, func(options *s3.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || ctx.Err() != nil || versioning == nil || versioning.Status != s3types.BucketVersioningStatusEnabled {
		return errRuntimeUnavailable
	}
	encryption, err := s3API.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(artifacts.Bucket), ExpectedBucketOwner: aws.String(artifacts.ExpectedBucketOwner)}, func(options *s3.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || ctx.Err() != nil || encryption == nil || encryption.ServerSideEncryptionConfiguration == nil || len(encryption.ServerSideEncryptionConfiguration.Rules) != 1 {
		return errRuntimeUnavailable
	}
	rule := encryption.ServerSideEncryptionConfiguration.Rules[0]
	if rule.ApplyServerSideEncryptionByDefault == nil || rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != s3types.ServerSideEncryptionAwsKms || aws.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID) != artifacts.KMSKeyARN || !aws.ToBool(rule.BucketKeyEnabled) {
		return errRuntimeUnavailable
	}
	key, err := kmsAPI.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(artifacts.KMSKeyARN)}, func(options *kms.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || ctx.Err() != nil || key == nil || key.KeyMetadata == nil {
		return errRuntimeUnavailable
	}
	metadata := key.KeyMetadata
	wantKeyID := strings.TrimPrefix(strings.Split(artifacts.KMSKeyARN, ":")[5], "key/")
	if aws.ToString(metadata.Arn) != artifacts.KMSKeyARN || aws.ToString(metadata.KeyId) != wantKeyID || aws.ToString(metadata.AWSAccountId) != artifacts.ExpectedBucketOwner || !metadata.Enabled || metadata.KeyManager != kmstypes.KeyManagerTypeCustomer || metadata.KeyState != kmstypes.KeyStateEnabled || metadata.KeyUsage != kmstypes.KeyUsageTypeEncryptDecrypt || metadata.KeySpec != kmstypes.KeySpecSymmetricDefault || metadata.Origin != kmstypes.OriginTypeAwsKms {
		return errRuntimeUnavailable
	}
	return nil
}

func readyProductionDiscoveryRole(ctx context.Context, api discoveryRoleReadinessAPI, cloud productionDiscoveryCloudConfig, artifacts productionDiscoveryArtifactConfig) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	role := discoveryAWSRolePattern.FindStringSubmatch(cloud.RoleARN)
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(api) || len(role) != 2 || role[1] != artifacts.ExpectedBucketOwner {
		return errRuntimeUnavailable
	}
	output, err := api.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	roleName := cloud.RoleARN[strings.LastIndex(cloud.RoleARN, "/")+1:]
	if err != nil || ctx.Err() != nil || output == nil || aws.ToString(output.Account) != artifacts.ExpectedBucketOwner || !strings.HasPrefix(aws.ToString(output.Arn), "arn:aws:sts::"+artifacts.ExpectedBucketOwner+":assumed-role/"+roleName+"/") {
		return errRuntimeUnavailable
	}
	return nil
}

type productionDiscoveryDependencies struct {
	Factory   discoveryCollectorFactory
	Queue     discoveryQueue
	ready     func(context.Context) error
	close     func() error
	closeOnce sync.Once
	closeErr  error
}

func newProductionDiscoveryDependencies(config productionDiscoveryDependencyConfig) (*productionDiscoveryDependencies, error) {
	if !validProductionDiscoveryDependencyAuthority(config) {
		return nil, errRuntimeUnavailable
	}
	cloud, err := newProductionDiscoveryCloudAuthority(config.Cloud)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	var queue productionDiscoveryQueue
	fail := func() (*productionDiscoveryDependencies, error) {
		_ = queue.Close()
		_ = cloud.Close()
		return nil, errRuntimeUnavailable
	}
	secrets, err := newDiscoverySecretsManagerReader(cloud.secrets, config.Cloud.SecretRoot, config.Cloud.Timeout)
	if err != nil {
		return fail()
	}
	providerHTTP, providerTransport, err := newDiscoveryProviderHTTPClient(config.ProviderTimeout)
	if err != nil {
		return fail()
	}
	github, err := newProductionDiscoveryGitHubTokenClient(providerHTTP, config.Cloud.Clock)
	if err != nil {
		providerTransport.CloseIdleConnections()
		return fail()
	}
	okta, err := newProductionDiscoveryOktaTokenClient(providerHTTP, config.Cloud.Clock)
	if err != nil {
		providerTransport.CloseIdleConnections()
		return fail()
	}
	credentials, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{
		Secrets: secrets, AssumeRole: cloud.assumeRole, GitHub: github, Okta: okta,
		GitHubAppID: config.GitHubAppID, GitHubPrivateKeyReference: config.GitHubPrivateKeyReference,
		OktaClientID: config.OktaClientID, OktaClientSecretReference: config.OktaClientSecretReference, Clock: config.Cloud.Clock,
	})
	if err != nil {
		providerTransport.CloseIdleConnections()
		return fail()
	}
	identity, err := newDiscoveryAWSCollectionIdentityCaller(cloud.NewCallerIdentity)
	if err != nil {
		providerTransport.CloseIdleConnections()
		return fail()
	}
	artifacts, err := newProductionDiscoveryArtifactAuthority(cloud.s3, config.Artifacts)
	if err != nil {
		providerTransport.CloseIdleConnections()
		return fail()
	}
	queue, err = newProductionDiscoveryQueue(cloud.sqs, productionDiscoveryQueueConfig{Region: config.Cloud.Region, QueueURL: config.QueueURL, OperationTimeout: config.QueueOperationTimeout, Visibility: config.LeaseDuration, ShutdownTimeout: config.ShutdownTimeout})
	if err != nil {
		providerTransport.CloseIdleConnections()
		return fail()
	}
	factory, err := newProductionLiveDiscoveryCollectorFactory(productionDiscoveryClientConfig{
		Artifacts: artifacts, Credentials: credentials, AWSIdentity: identity,
		AWSCollectorVersion: config.AWSCollectorVersion, KubernetesCollectorVersion: config.KubernetesCollectorVersion,
		GitHubCollectorVersion: config.GitHubCollectorVersion, OktaCollectorVersion: config.OktaCollectorVersion,
		ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion,
		KubernetesAllowedCIDRs: config.KubernetesAllowedCIDRs, ProviderTimeout: config.ProviderTimeout,
		ReadinessTimeout: config.ReadinessTimeout, Clock: config.Cloud.Clock,
	})
	if err != nil {
		providerTransport.CloseIdleConnections()
		return fail()
	}
	dependencies := &productionDiscoveryDependencies{Factory: factory, Queue: queue.Queue}
	dependencies.ready = func(ctx context.Context) error {
		if readyProductionDiscoveryDependencies(ctx, cloud, secrets, config) != nil || queue.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	dependencies.close = func() error {
		queueErr := queue.Close()
		providerTransport.CloseIdleConnections()
		cloudErr := cloud.Close()
		if queueErr != nil {
			return queueErr
		}
		return cloudErr
	}
	return dependencies, nil
}

func (dependencies *productionDiscoveryDependencies) Ready(ctx context.Context) error {
	if dependencies == nil || dependencies.ready == nil {
		return errRuntimeUnavailable
	}
	return dependencies.ready(ctx)
}

func (dependencies *productionDiscoveryDependencies) Close() error {
	if dependencies == nil {
		return nil
	}
	dependencies.closeOnce.Do(func() {
		if dependencies.close != nil {
			dependencies.closeErr = dependencies.close()
		}
	})
	return dependencies.closeErr
}

func readyProductionDiscoveryDependencies(ctx context.Context, cloud *productionDiscoveryCloudAuthority, secrets *discoverySecretsManagerReader, config productionDiscoveryDependencyConfig) error {
	if ctx == nil || ctx.Err() != nil || cloud == nil || cloud.credentials == nil || cloud.s3 == nil || secrets == nil {
		return errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, config.ReadinessTimeout)
	defer cancel()
	credentials, err := cloud.credentials.Retrieve(bounded)
	clearAWSCredentials(&credentials)
	if err != nil || bounded.Err() != nil {
		return errRuntimeUnavailable
	}
	if readyProductionDiscoveryRole(bounded, cloud.assumeRole, config.Cloud, config.Artifacts) != nil || readyProductionDiscoveryArtifactAuthority(bounded, cloud.s3, cloud.kms, config.Cloud, config.Artifacts) != nil {
		return errRuntimeUnavailable
	}
	for _, reference := range []string{config.GitHubPrivateKeyReference, config.OktaClientSecretReference} {
		value, secretErr := secrets.ResolveDiscoverySecret(bounded, reference)
		clear(value)
		if secretErr != nil || bounded.Err() != nil {
			return errRuntimeUnavailable
		}
	}
	return nil
}

func validProductionDiscoveryDependencyAuthority(config productionDiscoveryDependencyConfig) bool {
	role := discoveryAWSRolePattern.FindStringSubmatch(config.Cloud.RoleARN)
	kms := strings.Split(config.Artifacts.KMSKeyARN, ":")
	queue, queueErr := url.Parse(config.QueueURL)
	if len(role) != 2 || len(kms) != 6 || queueErr != nil || queue == nil || kms[0] != "arn" || kms[1] != "aws" || kms[2] != "kms" || kms[3] != config.Cloud.Region || kms[4] != config.Artifacts.ExpectedBucketOwner || role[1] != config.Artifacts.ExpectedBucketOwner || !strings.HasPrefix(kms[5], "key/") {
		return false
	}
	queueParts := strings.Split(strings.TrimPrefix(queue.Path, "/"), "/")
	if !validSQSURL(config.QueueURL) || queue.Hostname() != "sqs."+config.Cloud.Region+".amazonaws.com" || len(queueParts) != 2 || queueParts[0] != role[1] || queueParts[1] != "agentsec-discovery-jobs" {
		return false
	}
	return validProductionDiscoveryCloudConfig(config.Cloud) &&
		validDiscoveryCredentialReference(config.GitHubPrivateKeyReference, "ref:github/") &&
		validDiscoveryCredentialReference(config.OktaClientSecretReference, "ref:okta/") &&
		validDiscoveryCIDRs(config.KubernetesAllowedCIDRs) && config.ProviderTimeout >= 100*time.Millisecond && config.ProviderTimeout <= 30*time.Second &&
		config.ReadinessTimeout >= time.Second && config.ReadinessTimeout <= 10*time.Second
}
