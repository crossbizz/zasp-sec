package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

type discoveryCredentialMaterialResolverStub struct{}

func (*discoveryCredentialMaterialResolverStub) ResolveDiscoveryCredential(context.Context, discoveryCredentialMaterialRequest) (*collection.CredentialMaterial, error) {
	return nil, errDiscoveryCredentialUnavailable
}

type discoveryInventoryCallerStub struct{}

func (*discoveryInventoryCallerStub) GetCollectionInventory(context.Context, []byte) (awsdiscovery.CollectionInventory, error) {
	cartography := json.RawMessage(`{"account_id":"123456789012","managed_policies":{},"roles":[]}`)
	prowler := json.RawMessage(`{"account_id":"123456789012","instances":[],"roles":[]}`)
	return awsdiscovery.CollectionInventory{Identity: awsdiscovery.Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/zasp/session"}, CredentialExpiresAt: time.Now().UTC().Add(10 * time.Minute), CartographySource: cartography, CartographyDigest: sha256.Sum256(cartography), ProwlerSource: prowler, ProwlerDigest: sha256.Sum256(prowler)}, nil
}

func (*discoveryInventoryCallerStub) CheckCollectionReadiness(context.Context) error { return nil }

type discoverySecurityAnalyzerStub struct{}

func (*discoverySecurityAnalyzerStub) CheckCollectionReadiness(context.Context) error { return nil }

func (*discoverySecurityAnalyzerStub) Collect(_ context.Context, request awsdiscovery.CollectionSecurityRequest, _ []byte) (awsdiscovery.CollectionSecurityResult, error) {
	result := json.RawMessage(`{"findings":[],"version":"5.39.1"}`)
	if request.Mode == awsdiscovery.SecurityModeCartographyAWS {
		result = json.RawMessage(`{"policies":[],"roles":[],"version":"0.139.1"}`)
	}
	return awsdiscovery.CollectionSecurityResult{Mode: request.Mode, SourceDigest: request.SourceDigest, Result: result}, nil
}

func TestProductionLiveDiscoveryCollectorFactoryBuildsExactJobRegistry(t *testing.T) {
	now := time.Now().UTC()
	artifacts, err := newProductionDiscoveryArtifactAuthority(&discoveryS3APIStub{}, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := newProductionLiveDiscoveryCollectorFactory(productionDiscoveryClientConfig{Artifacts: artifacts, Credentials: &discoveryCredentialMaterialResolverStub{}, AWSInventory: &discoveryInventoryCallerStub{}, AWSSecurity: &discoverySecurityAnalyzerStub{}, AWSCollectorVersion: "collector_v1", KubernetesCollectorVersion: "kubernetes_v1", GitHubCollectorVersion: "github_v1", OktaCollectorVersion: "okta_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", KubernetesAllowedCIDRs: []string{"203.0.113.0/24"}, ProviderTimeout: time.Second, ReadinessTimeout: time.Second, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	scope := discoveryCredentialScope(t)
	input := discoveryCredentialInput(scope, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/external-id/customer-0001", collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp/discovery"}`, now)
	input.ObservationTime = now.Truncate(time.Second)
	collector, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: "lease-token-0000000000000001"})
	if err != nil || collector == nil {
		t.Fatalf("collector=%#v err=%v", collector, err)
	}
	collector.Destroy()
}

func TestProductionLiveDiscoveryCollectorFactoryRejectsJobVersionDriftBeforeDependencies(t *testing.T) {
	now := time.Now().UTC()
	artifacts, err := newProductionDiscoveryArtifactAuthority(&discoveryS3APIStub{}, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := newProductionLiveDiscoveryCollectorFactory(productionDiscoveryClientConfig{Artifacts: artifacts, Credentials: &discoveryCredentialMaterialResolverStub{}, AWSInventory: &discoveryInventoryCallerStub{}, AWSSecurity: &discoverySecurityAnalyzerStub{}, AWSCollectorVersion: "collector_v1", KubernetesCollectorVersion: "kubernetes_v1", GitHubCollectorVersion: "github_v1", OktaCollectorVersion: "okta_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", KubernetesAllowedCIDRs: []string{"203.0.113.0/24"}, ProviderTimeout: time.Second, ReadinessTimeout: time.Second, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	scope := discoveryCredentialScope(t)
	valid := discoveryCredentialInput(scope, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/external-id/customer-0001", collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp/discovery"}`, now)
	valid.ObservationTime = now.Truncate(time.Second)
	for _, mutate := range []func(*apiserver.ExecutionJobInput){
		func(input *apiserver.ExecutionJobInput) { input.CollectorVersion = "hostile_v1" },
		func(input *apiserver.ExecutionJobInput) { input.ParserVersion = "hostile_v1" },
		func(input *apiserver.ExecutionJobInput) { input.ToolVersion = "hostile_v1" },
	} {
		input := valid
		mutate(&input)
		if collector, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: "lease-token-0000000000000001"}); err == nil || collector != nil {
			t.Fatal("version drift constructed collector")
		}
	}
}

func TestProductionLiveDiscoveryCollectorFactoryRejectsUnionOrAmbientAuthority(t *testing.T) {
	artifacts, err := newProductionDiscoveryArtifactAuthority(&discoveryS3APIStub{}, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	valid := productionDiscoveryClientConfig{Artifacts: artifacts, Credentials: &discoveryCredentialMaterialResolverStub{}, AWSInventory: &discoveryInventoryCallerStub{}, AWSSecurity: &discoverySecurityAnalyzerStub{}, AWSCollectorVersion: "collector_v1", KubernetesCollectorVersion: "kubernetes_v1", GitHubCollectorVersion: "github_v1", OktaCollectorVersion: "okta_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", KubernetesAllowedCIDRs: []string{"203.0.113.0/24"}, ProviderTimeout: time.Second, ReadinessTimeout: time.Second, Clock: func() time.Time { return time.Now().UTC() }}
	tests := []func(*productionDiscoveryClientConfig){
		func(config *productionDiscoveryClientConfig) { config.Artifacts = nil },
		func(config *productionDiscoveryClientConfig) { config.Credentials = nil },
		func(config *productionDiscoveryClientConfig) { config.AWSInventory = nil },
		func(config *productionDiscoveryClientConfig) { config.AWSSecurity = nil },
		func(config *productionDiscoveryClientConfig) { config.KubernetesAllowedCIDRs = []string{"0.0.0.0/0"} },
		func(config *productionDiscoveryClientConfig) { config.ProviderTimeout = 0 },
		func(config *productionDiscoveryClientConfig) { config.AWSCollectorVersion = "" },
		func(config *productionDiscoveryClientConfig) { config.ParserVersion = "" },
		func(config *productionDiscoveryClientConfig) { config.Clock = nil },
	}
	for index, mutate := range tests {
		config := valid
		mutate(&config)
		if _, err := newProductionLiveDiscoveryCollectorFactory(config); err == nil {
			t.Fatalf("hostile config %d accepted", index)
		}
	}
}

var _ discoveryCredentialMaterialResolver = (*discoveryCredentialMaterialResolverStub)(nil)
var _ awsdiscovery.CollectionInventoryCaller = (*discoveryInventoryCallerStub)(nil)
var _ awsdiscovery.CollectionSecurityAnalyzer = (*discoverySecurityAnalyzerStub)(nil)
