package main

import (
	"context"
	"strings"
	"sync"
	"time"
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
}

type productionDiscoveryDependencies struct {
	Factory   discoveryCollectorFactory
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
	fail := func() (*productionDiscoveryDependencies, error) {
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
	dependencies := &productionDiscoveryDependencies{Factory: factory}
	dependencies.ready = func(ctx context.Context) error {
		return readyProductionDiscoveryDependencies(ctx, cloud, secrets, config)
	}
	dependencies.close = func() error {
		providerTransport.CloseIdleConnections()
		return cloud.Close()
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
	if len(role) != 2 || len(kms) != 6 || kms[0] != "arn" || kms[1] != "aws" || kms[2] != "kms" || kms[3] != config.Cloud.Region || kms[4] != config.Artifacts.ExpectedBucketOwner || role[1] != config.Artifacts.ExpectedBucketOwner || !strings.HasPrefix(kms[5], "key/") {
		return false
	}
	return validProductionDiscoveryCloudConfig(config.Cloud) &&
		validDiscoveryCredentialReference(config.GitHubPrivateKeyReference, "ref:github/") &&
		validDiscoveryCredentialReference(config.OktaClientSecretReference, "ref:okta/") &&
		validDiscoveryCIDRs(config.KubernetesAllowedCIDRs) && config.ProviderTimeout >= 100*time.Millisecond && config.ProviderTimeout <= 30*time.Second &&
		config.ReadinessTimeout >= time.Second && config.ReadinessTimeout <= 10*time.Second
}
