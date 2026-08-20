package main

import (
	"context"
	"testing"
	"time"
)

func TestProductionDiscoveryDependenciesComposeExplicitAuthorities(t *testing.T) {
	now := time.Now().UTC()
	config := validProductionDiscoveryDependencyConfig(now)
	dependencies, err := newProductionDiscoveryDependencies(config)
	if err != nil {
		t.Fatal(err)
	}
	if dependencies.Factory == nil || dependencies.ready == nil || dependencies.close == nil {
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
	}
}
