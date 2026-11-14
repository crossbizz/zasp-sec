package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type discoveryCredentialMaterialResolverStub struct{}

func (*discoveryCredentialMaterialResolverStub) ResolveDiscoveryCredential(context.Context, discoveryCredentialMaterialRequest) (*collection.CredentialMaterial, error) {
	return nil, errDiscoveryCredentialUnavailable
}

type discoveryInventoryCallerStub struct{}

func (*discoveryInventoryCallerStub) GetCollectionInventory(context.Context, []byte) (awsdiscovery.CollectionInventory, error) {
	cartography := json.RawMessage(`{"account_id":"123456789012","managed_policies":{},"roles":[]}`)
	prowler := json.RawMessage(`{"account_id":"123456789012","instances":[],"roles":[]}`)
	agents := json.RawMessage(`{"account_id":"123456789012","bedrock_agents":[],"gateways":[],"lambda_functions":[],"runtimes":[],"services":[{"service":"bedrock-agent","status":"collected"},{"service":"bedrock-agentcore","status":"collected"},{"service":"lambda","status":"collected"}]}`)
	return awsdiscovery.CollectionInventory{Identity: awsdiscovery.Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/zasp/session"}, CredentialExpiresAt: time.Now().UTC().Truncate(time.Second).Add(10 * time.Minute), CartographySource: cartography, CartographyDigest: sha256.Sum256(cartography), ProwlerSource: prowler, ProwlerDigest: sha256.Sum256(prowler), AgentSource: agents, AgentDigest: sha256.Sum256(agents)}, nil
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
	var product apiserver.DiscoveryCollectionInput
	raw, _ := json.Marshal(input)
	if err := json.Unmarshal(raw, &product); err != nil {
		t.Fatal(err)
	}
	product.EffectID = strings.Repeat("a", 64)
	product.Deadline = now.Add(time.Hour)
	collector, err = factory.BuildProductDiscoveryCollector(context.Background(), scope, product, func(context.Context) error { return nil })
	if err != nil || collector == nil {
		t.Fatalf("product collector=%#v err=%v", collector, err)
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

func saasCompositionConfig(t *testing.T, now time.Time) productionDiscoveryClientConfig {
	t.Helper()
	artifacts, err := newProductionDiscoveryArtifactAuthority(&discoveryS3APIStub{}, productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return productionDiscoveryClientConfig{Artifacts: artifacts, Credentials: &discoveryCredentialMaterialResolverStub{}, AWSInventory: &discoveryInventoryCallerStub{}, AWSSecurity: &discoverySecurityAnalyzerStub{}, AWSCollectorVersion: "collector_v1", KubernetesCollectorVersion: "kubernetes_v1", GitHubCollectorVersion: "github_v1", OktaCollectorVersion: "okta_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", KubernetesAllowedCIDRs: []string{"203.0.113.0/24"}, ProviderTimeout: time.Second, ReadinessTimeout: time.Second, Clock: func() time.Time { return now }}
}

func saasCompositionRegistrations(t *testing.T, factory *productionLiveDiscoveryCollectorFactory, scope domain.Scope, now time.Time) map[collection.Provider]firstPartyProviderClientRegistration {
	t.Helper()
	providers, err := factory.collectionFactoryForAuthority(awsdiscovery.CollectionInventoryAuthority{Scope: scope, IntegrationID: discoveryCredentialID(5), ConnectionID: discoveryCredentialID(6), JobID: discoveryCredentialID(4), Attempt: 1, ObservedAt: now.Truncate(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	firstParty, ok := providers.(*firstPartyCollectionFactory)
	if !ok {
		t.Fatalf("collection factory = %T", providers)
	}
	registrations := make(map[collection.Provider]firstPartyProviderClientRegistration, len(firstParty.registrations))
	for _, registration := range firstParty.registrations {
		if _, duplicate := registrations[registration.Provider]; duplicate {
			t.Fatalf("provider %s registered twice", registration.Provider)
		}
		registrations[registration.Provider] = registration
	}
	return registrations
}

// A deployment that configures neither optional collector registers exactly
// the four required providers, and refuses a Microsoft or Salesforce job
// before any dependency is touched.
func TestProductionLiveDiscoveryCollectorFactoryRegistersOnlyTheRequiredProvidersByDefault(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	factory, err := newProductionLiveDiscoveryCollectorFactory(saasCompositionConfig(t, now))
	if err != nil {
		t.Fatal(err)
	}
	registrations := saasCompositionRegistrations(t, factory, scope, now)
	want := map[collection.Provider]collection.CredentialClass{collection.ProviderAWS: collection.CredentialAWSAssumeRole, collection.ProviderKubernetes: collection.CredentialKubernetesCluster, collection.ProviderGitHub: collection.CredentialGitHubInstallation, collection.ProviderOkta: collection.CredentialOktaRefresh}
	if len(registrations) != len(want) {
		t.Fatalf("registrations = %d, want the four required providers", len(registrations))
	}
	for provider, class := range want {
		if registration, ok := registrations[provider]; !ok || registration.CredentialClass != class {
			t.Fatalf("%s registration = %#v, %t", provider, registration, ok)
		}
	}
	if factory.collectorVersion(collection.ProviderMicrosoft) != "" || factory.collectorVersion(collection.ProviderSalesforce) != "" {
		t.Fatal("an unconfigured provider reported a collector version")
	}
	for _, input := range []apiserver.ExecutionJobInput{microsoftCredentialInput(scope, testMicrosoftConfig, now), salesforceCredentialInput(scope, testSalesforceConfig, now)} {
		input.ObservationTime = now.Truncate(time.Second)
		for _, version := range []string{"collector_v1", ""} {
			input.CollectorVersion = version
			if collector, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: "lease-token-0000000000000001"}); err == nil || collector != nil {
				t.Fatalf("%s job with collector version %q built a collector where the provider is not served", input.Provider, version)
			}
		}
	}
}

func TestProductionLiveDiscoveryCollectorFactoryRegistersEachConfiguredOptionalProvider(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	tests := []struct {
		name                  string
		microsoft, salesforce string
	}{
		{"microsoft only", "microsoft_v1", ""},
		{"salesforce only", "", "salesforce_v1"},
		{"both", "microsoft_v1", "salesforce_v1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := saasCompositionConfig(t, now)
			config.MicrosoftCollectorVersion, config.SalesforceCollectorVersion = test.microsoft, test.salesforce
			factory, err := newProductionLiveDiscoveryCollectorFactory(config)
			if err != nil {
				t.Fatal(err)
			}
			registrations := saasCompositionRegistrations(t, factory, scope, now)
			wantCount := 4
			for _, optional := range []struct {
				provider collection.Provider
				class    collection.CredentialClass
				version  string
				input    apiserver.ExecutionJobInput
			}{
				{collection.ProviderMicrosoft, collection.CredentialMicrosoftClient, test.microsoft, microsoftCredentialInput(scope, testMicrosoftConfig, now)},
				{collection.ProviderSalesforce, collection.CredentialSalesforceClient, test.salesforce, salesforceCredentialInput(scope, testSalesforceConfig, now)},
			} {
				registration, registered := registrations[optional.provider]
				input := optional.input
				input.ObservationTime = now.Truncate(time.Second)
				input.CollectorVersion = optional.version
				if optional.version == "" {
					input.CollectorVersion = "collector_v1"
				}
				collector, buildErr := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: "lease-token-0000000000000001"})
				if optional.version == "" {
					if registered || buildErr == nil || collector != nil {
						t.Fatalf("%s is registered or collects without a configured version", optional.provider)
					}
					continue
				}
				wantCount++
				if !registered || registration.CredentialClass != optional.class || registration.CollectorVersion != optional.version || registration.Client == nil || registration.Readiness == nil {
					t.Fatalf("%s registration = %#v, %t", optional.provider, registration, registered)
				}
				if factory.collectorVersion(optional.provider) != optional.version {
					t.Fatalf("%s collector version = %q", optional.provider, factory.collectorVersion(optional.provider))
				}
				if buildErr != nil || collector == nil {
					t.Fatalf("%s collector=%v err=%v", optional.provider, collector != nil, buildErr)
				}
				collector.Destroy()
				// The job must name the configured version and the provider's own class.
				input.CollectorVersion = "collector_v2"
				if drifted, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: "lease-token-0000000000000001"}); err == nil || drifted != nil {
					t.Fatalf("%s version drift built a collector", optional.provider)
				}
			}
			if len(registrations) != wantCount {
				t.Fatalf("registrations = %d, want %d", len(registrations), wantCount)
			}
			// The four required providers are unchanged.
			if registrations[collection.ProviderAWS].CredentialClass != collection.CredentialAWSAssumeRole || registrations[collection.ProviderOkta].CollectorVersion != "okta_v1" {
				t.Fatalf("required registrations changed: %#v", registrations)
			}
		})
	}
}

func TestProductionLiveDiscoveryCollectorFactoryRefusesAnInvalidOptionalCollectorVersion(t *testing.T) {
	now := time.Now().UTC()
	for _, version := range []string{"Microsoft_V1", "1collector", "v", "collector v1", "collector/v1", strings.Repeat("a", 65), " collector_v1"} {
		for _, set := range []func(*productionDiscoveryClientConfig){
			func(config *productionDiscoveryClientConfig) { config.MicrosoftCollectorVersion = version },
			func(config *productionDiscoveryClientConfig) { config.SalesforceCollectorVersion = version },
		} {
			config := saasCompositionConfig(t, now)
			set(&config)
			if _, err := newProductionLiveDiscoveryCollectorFactory(config); err == nil {
				t.Fatalf("invalid optional collector version %q accepted", version)
			}
		}
	}
}

// The registration set is the four required providers plus optional ones,
// each with its own credential class and at most once.
func TestFirstPartyCollectionFactoryRequiresTheFourAndAdmitsOnlyKnownOptionalProviders(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	config := saasCompositionConfig(t, now)
	config.MicrosoftCollectorVersion, config.SalesforceCollectorVersion = "microsoft_v1", "salesforce_v1"
	factory, err := newProductionLiveDiscoveryCollectorFactory(config)
	if err != nil {
		t.Fatal(err)
	}
	all := saasCompositionRegistrations(t, factory, scope, now)
	ordered := func(providers ...collection.Provider) []firstPartyProviderClientRegistration {
		result := make([]firstPartyProviderClientRegistration, 0, len(providers))
		for _, provider := range providers {
			result = append(result, all[provider])
		}
		return result
	}
	required := []collection.Provider{collection.ProviderAWS, collection.ProviderKubernetes, collection.ProviderGitHub, collection.ProviderOkta}
	for _, valid := range [][]collection.Provider{required, append(append([]collection.Provider(nil), required...), collection.ProviderMicrosoft), append(append([]collection.Provider(nil), required...), collection.ProviderSalesforce), append(append([]collection.Provider(nil), required...), collection.ProviderSalesforce, collection.ProviderMicrosoft)} {
		if _, err := newFirstPartyCollectionFactory(ordered(valid...)); err != nil {
			t.Fatalf("registrations %v refused: %v", valid, err)
		}
	}
	for name, hostile := range map[string][]firstPartyProviderClientRegistration{
		"three required":                         ordered(collection.ProviderAWS, collection.ProviderKubernetes, collection.ProviderGitHub),
		"an optional provider replaces okta":     ordered(collection.ProviderAWS, collection.ProviderKubernetes, collection.ProviderGitHub, collection.ProviderMicrosoft),
		"both optional providers replace two":    ordered(collection.ProviderAWS, collection.ProviderKubernetes, collection.ProviderMicrosoft, collection.ProviderSalesforce),
		"an optional provider registered twice":  ordered(collection.ProviderAWS, collection.ProviderKubernetes, collection.ProviderGitHub, collection.ProviderOkta, collection.ProviderMicrosoft, collection.ProviderMicrosoft),
		"seven registrations":                    append(ordered(append(append([]collection.Provider(nil), required...), collection.ProviderMicrosoft, collection.ProviderSalesforce)...), all[collection.ProviderAWS]),
		"microsoft with the salesforce class":    append(ordered(required...), firstPartyProviderClientRegistration{Provider: collection.ProviderMicrosoft, CollectorVersion: "microsoft_v1", CredentialClass: collection.CredentialSalesforceClient, Client: all[collection.ProviderMicrosoft].Client, Readiness: all[collection.ProviderMicrosoft].Readiness, ReadinessTimeout: time.Second}),
		"salesforce with the okta refresh class": append(ordered(required...), firstPartyProviderClientRegistration{Provider: collection.ProviderSalesforce, CollectorVersion: "salesforce_v1", CredentialClass: collection.CredentialOktaRefresh, Client: all[collection.ProviderSalesforce].Client, Readiness: all[collection.ProviderSalesforce].Readiness, ReadinessTimeout: time.Second}),
		"an optional provider without a client":  append(ordered(required...), firstPartyProviderClientRegistration{Provider: collection.ProviderMicrosoft, CollectorVersion: "microsoft_v1", CredentialClass: collection.CredentialMicrosoftClient, Readiness: all[collection.ProviderMicrosoft].Readiness, ReadinessTimeout: time.Second}),
	} {
		if _, err := newFirstPartyCollectionFactory(hostile); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// The two optional collector versions are read from their own variables. An
// unset variable leaves the provider out; a set one must be a valid version.
func TestWorkerRuntimeConfigReadsTheOptionalCollectorVersions(t *testing.T) {
	unset, err := loadWorkerRuntimeConfig(mapLookup(validDiscoveryRuntimeEnvironment()))
	if err != nil || unset.MicrosoftCollectorVersion != "" || unset.SalesforceCollectorVersion != "" {
		t.Fatalf("config without the optional versions: %q %q %v", unset.MicrosoftCollectorVersion, unset.SalesforceCollectorVersion, err)
	}
	if dependencies := productionDiscoveryDependenciesConfig(unset); dependencies.MicrosoftCollectorVersion != "" || dependencies.SalesforceCollectorVersion != "" {
		t.Fatalf("dependency config invented an optional version: %#v", dependencies)
	}
	values := validDiscoveryRuntimeEnvironment()
	values["ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION"], values["ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION"] = "collector_v1", "salesforce-collector-v1"
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil || config.MicrosoftCollectorVersion != "collector_v1" || config.SalesforceCollectorVersion != "salesforce-collector-v1" {
		t.Fatalf("optional collector versions = %q, %q, %v", config.MicrosoftCollectorVersion, config.SalesforceCollectorVersion, err)
	}
	if dependencies := productionDiscoveryDependenciesConfig(config); dependencies.MicrosoftCollectorVersion != "collector_v1" || dependencies.SalesforceCollectorVersion != "salesforce-collector-v1" {
		t.Fatalf("dependency config dropped the optional versions: %#v", dependencies)
	}
	for _, name := range []string{"ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION", "ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION"} {
		for _, invalid := range []string{"Collector_V1", "1", "collector v1", "v"} {
			hostile := validDiscoveryRuntimeEnvironment()
			hostile[name] = invalid
			if _, err := loadWorkerRuntimeConfig(mapLookup(hostile)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("%s=%q error = %v", name, invalid, err)
			}
		}
	}
}
