package main

import (
	"context"
	"net"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/microsoftdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	saasplatforms "github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/salesforcediscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// MicrosoftCollectorVersion and SalesforceCollectorVersion are optional. An
// empty version leaves the provider unregistered: its jobs are refused and
// the four required providers behave as before.
type productionDiscoveryClientConfig struct {
	Artifacts                  artifactstore.ObjectReferencingArtifactStore
	Credentials                discoveryCredentialMaterialResolver
	AWSInventory               awsdiscovery.CollectionInventoryCaller
	AWSSecurity                awsdiscovery.CollectionSecurityAnalyzer
	AWSCollectorVersion        string
	KubernetesCollectorVersion string
	GitHubCollectorVersion     string
	OktaCollectorVersion       string
	MicrosoftCollectorVersion  string
	SalesforceCollectorVersion string
	// SaaSCollectorVersion and SaaSProxy serve the generic saas provider:
	// both are set or neither is.
	SaaSCollectorVersion   string
	SaaSProxy              saasdiscovery.Proxy
	ParserVersion          string
	ToolVersion            string
	KubernetesAllowedCIDRs []string
	KubernetesNetwork      *kubernetesdiscovery.CollectionNetwork
	ProviderTimeout        time.Duration
	ReadinessTimeout       time.Duration
	Clock                  func() time.Time
}

type productionLiveDiscoveryCollectorFactory struct {
	config productionDiscoveryClientConfig
}

func newProductionLiveDiscoveryCollectorFactory(config productionDiscoveryClientConfig) (*productionLiveDiscoveryCollectorFactory, error) {
	if nilWorkerDependency(config.Artifacts) || nilWorkerDependency(config.Credentials) || nilWorkerDependency(config.AWSInventory) || nilWorkerDependency(config.AWSSecurity) || config.Clock == nil || config.ProviderTimeout < 100*time.Millisecond || config.ProviderTimeout > 30*time.Second || config.ReadinessTimeout < 100*time.Millisecond || config.ReadinessTimeout > 10*time.Second || !validDiscoveryCIDRs(config.KubernetesAllowedCIDRs) {
		return nil, errRuntimeUnavailable
	}
	for _, version := range []string{config.AWSCollectorVersion, config.KubernetesCollectorVersion, config.GitHubCollectorVersion, config.OktaCollectorVersion, config.ParserVersion, config.ToolVersion} {
		if !discoveryCollectorVersionPattern.MatchString(version) {
			return nil, errRuntimeUnavailable
		}
	}
	for _, version := range []string{config.MicrosoftCollectorVersion, config.SalesforceCollectorVersion, config.SaaSCollectorVersion} {
		if version != "" && !discoveryCollectorVersionPattern.MatchString(version) {
			return nil, errRuntimeUnavailable
		}
	}
	if (config.SaaSCollectorVersion != "") == nilWorkerDependency(config.SaaSProxy) {
		return nil, errRuntimeUnavailable
	}
	now := config.Clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errRuntimeUnavailable
	}
	config.KubernetesAllowedCIDRs = append([]string(nil), config.KubernetesAllowedCIDRs...)
	return &productionLiveDiscoveryCollectorFactory{config: config}, nil
}

func (factory *productionLiveDiscoveryCollectorFactory) BuildDiscoveryCollector(ctx context.Context, binding discoveryCollectorBinding) (discoveryJobCollector, error) {
	if factory == nil || ctx == nil || ctx.Err() != nil || !validDiscoveryExecutionInput(binding.Scope, binding.Input.JobID, binding.Input) ||
		binding.Input.CollectorVersion != factory.collectorVersion(binding.Input.Provider) || binding.Input.ParserVersion != factory.config.ParserVersion || binding.Input.ToolVersion != factory.config.ToolVersion {
		return nil, errWorkerExecution
	}
	providerFactory, err := factory.collectionFactory(binding)
	if err != nil {
		return nil, errWorkerExecution
	}
	boundFactory, err := newProductionDiscoveryCollectorFactory(providerFactory, factory.config.Credentials)
	if err != nil {
		return nil, errWorkerExecution
	}
	return boundFactory.BuildDiscoveryCollector(ctx, binding)
}

func (factory *productionLiveDiscoveryCollectorFactory) collectionFactory(binding discoveryCollectorBinding) (collection.CollectorFactory, error) {
	integrationID, integrationErr := domain.ParseProductID(binding.Input.IntegrationID)
	connectionID, connectionErr := domain.ParseProductID(binding.Input.ConnectionID)
	jobID, jobErr := domain.ParseProductID(binding.Input.JobID)
	if integrationErr != nil || connectionErr != nil || jobErr != nil {
		return nil, errRuntimeUnavailable
	}
	return factory.collectionFactoryForAuthority(awsdiscovery.CollectionInventoryAuthority{
		Scope: binding.Scope, IntegrationID: integrationID, ConnectionID: connectionID, JobID: jobID,
		Attempt: binding.Input.Attempt, ObservedAt: binding.Input.ObservationTime,
	})
}

func (factory *productionLiveDiscoveryCollectorFactory) BuildProductDiscoveryCollector(ctx context.Context, scope domain.Scope, input apiserver.DiscoveryCollectionInput, check func(context.Context) error) (discoveryJobCollector, error) {
	if factory == nil || ctx == nil || ctx.Err() != nil || check == nil || input.CollectorVersion != factory.collectorVersion(input.Provider) || input.ParserVersion != factory.config.ParserVersion || input.ToolVersion != factory.config.ToolVersion {
		return nil, errWorkerExecution
	}
	request, err := input.CollectionRequest(scope)
	if err != nil {
		return nil, errWorkerExecution
	}
	providers, err := factory.collectionFactoryForAuthority(awsdiscovery.CollectionInventoryAuthority{Scope: scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID, JobID: request.JobID, EffectID: input.EffectID, ObservedAt: input.ObservationTime})
	if err != nil {
		return nil, errWorkerExecution
	}
	bound, err := newProductionDiscoveryCollectorFactory(providers, factory.config.Credentials)
	if err != nil {
		return nil, errWorkerExecution
	}
	return bound.BuildProductDiscoveryCollector(ctx, scope, input, check)
}

func (factory *productionLiveDiscoveryCollectorFactory) collectionFactoryForAuthority(authority awsdiscovery.CollectionInventoryAuthority) (collection.CollectorFactory, error) {
	awsAPI, err := awsdiscovery.NewInventoryCollectionAPI(factory.config.AWSInventory, factory.config.AWSSecurity, authority, discoveryAWSInventoryPageTimeout)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	githubAPI, err := githubdiscovery.NewInstallationCollectionAPI(factory.config.ProviderTimeout)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	kubernetesAPI := &discoveryBearerCollectionAPI{provider: collection.ProviderKubernetes, kubernetes: func(config kubernetesdiscovery.PinnedCollectionAPIConfig) (kubernetesdiscovery.CollectionAPI, error) {
		if network := factory.config.KubernetesNetwork; network != nil {
			return kubernetesdiscovery.NewPinnedKubernetesCollectionAPIWithNetwork(config, *network)
		}
		return kubernetesdiscovery.NewPinnedKubernetesCollectionAPI(config)
	}, allowedCIDRs: append([]string(nil), factory.config.KubernetesAllowedCIDRs...), timeout: factory.config.ProviderTimeout}
	githubBearerAPI := &discoveryBearerCollectionAPI{provider: collection.ProviderGitHub, github: githubAPI, timeout: factory.config.ProviderTimeout}
	oktaAPI := &discoveryBearerCollectionAPI{provider: collection.ProviderOkta, okta: func(issuer string, timeout time.Duration) (idpdiscovery.CollectionAPI, error) {
		return idpdiscovery.NewOktaCollectionAPI(issuer, timeout)
	}, timeout: factory.config.ProviderTimeout}

	awsClient, err := awsdiscovery.NewCollectionClient(awsAPI, factory.config.Artifacts, awsdiscovery.CollectionClientConfig{CollectorVersion: factory.config.AWSCollectorVersion, ParserVersion: factory.config.ParserVersion, ToolVersion: factory.config.ToolVersion, Clock: factory.config.Clock})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	githubClient, err := githubdiscovery.NewCollectionClient(githubBearerAPI, factory.config.Artifacts, githubdiscovery.CollectionClientConfig{CollectorVersion: factory.config.GitHubCollectorVersion, ParserVersion: factory.config.ParserVersion, ToolVersion: factory.config.ToolVersion, Clock: factory.config.Clock})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	kubernetesClient, err := kubernetesdiscovery.NewCollectionClient(kubernetesAPI, factory.config.Artifacts, kubernetesdiscovery.CollectionClientConfig{CollectorVersion: factory.config.KubernetesCollectorVersion, ParserVersion: factory.config.ParserVersion, ToolVersion: factory.config.ToolVersion, Clock: factory.config.Clock})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	oktaClient, err := idpdiscovery.NewOktaCollectionClient(oktaAPI, factory.config.Artifacts, idpdiscovery.CollectionClientConfig{CollectorVersion: factory.config.OktaCollectorVersion, ParserVersion: factory.config.ParserVersion, ToolVersion: factory.config.ToolVersion, Clock: factory.config.Clock})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	awsReadiness, awsOK := awsClient.(collection.ReadinessProbe)
	kubernetesReadiness, kubernetesOK := kubernetesClient.(collection.ReadinessProbe)
	githubReadiness, githubOK := githubClient.(collection.ReadinessProbe)
	oktaReadiness, oktaOK := oktaClient.(collection.ReadinessProbe)
	if !awsOK || !kubernetesOK || !githubOK || !oktaOK || nilWorkerDependency(awsReadiness) || nilWorkerDependency(kubernetesReadiness) || nilWorkerDependency(githubReadiness) || nilWorkerDependency(oktaReadiness) {
		return nil, errRuntimeUnavailable
	}
	registrations := []firstPartyProviderClientRegistration{
		{Provider: collection.ProviderAWS, CollectorVersion: factory.config.AWSCollectorVersion, CredentialClass: collection.CredentialAWSAssumeRole, Client: awsClient, Readiness: awsReadiness, ReadinessTimeout: factory.config.ReadinessTimeout},
		{Provider: collection.ProviderKubernetes, CollectorVersion: factory.config.KubernetesCollectorVersion, CredentialClass: collection.CredentialKubernetesCluster, Client: kubernetesClient, Readiness: kubernetesReadiness, ReadinessTimeout: factory.config.ReadinessTimeout},
		{Provider: collection.ProviderGitHub, CollectorVersion: factory.config.GitHubCollectorVersion, CredentialClass: collection.CredentialGitHubInstallation, Client: githubClient, Readiness: githubReadiness, ReadinessTimeout: factory.config.ReadinessTimeout},
		{Provider: collection.ProviderOkta, CollectorVersion: factory.config.OktaCollectorVersion, CredentialClass: collection.CredentialOktaRefresh, Client: oktaClient, Readiness: oktaReadiness, ReadinessTimeout: factory.config.ReadinessTimeout},
	}
	if version := factory.config.MicrosoftCollectorVersion; version != "" {
		api, err := microsoftdiscovery.NewMicrosoftCollectionAPI(microsoftdiscovery.CollectionAPIConfig{Timeout: factory.config.ProviderTimeout, Clock: factory.config.Clock})
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		client, err := microsoftdiscovery.NewMicrosoftCollectionClient(&discoveryBearerCollectionAPI{provider: collection.ProviderMicrosoft, microsoft: api, timeout: factory.config.ProviderTimeout}, factory.config.Artifacts, microsoftdiscovery.CollectionClientConfig{CollectorVersion: version, ParserVersion: factory.config.ParserVersion, ToolVersion: factory.config.ToolVersion, Clock: factory.config.Clock})
		registration, err := factory.optionalRegistration(collection.ProviderMicrosoft, collection.CredentialMicrosoftClient, version, client, err)
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		registrations = append(registrations, registration)
	}
	if version := factory.config.SalesforceCollectorVersion; version != "" {
		api, err := salesforcediscovery.NewSalesforceCollectionAPI(salesforcediscovery.CollectionAPIConfig{Timeout: factory.config.ProviderTimeout, Clock: factory.config.Clock})
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		client, err := salesforcediscovery.NewSalesforceCollectionClient(&discoveryBearerCollectionAPI{provider: collection.ProviderSalesforce, salesforce: api, timeout: factory.config.ProviderTimeout}, factory.config.Artifacts, salesforcediscovery.CollectionClientConfig{CollectorVersion: version, ParserVersion: factory.config.ParserVersion, ToolVersion: factory.config.ToolVersion, Clock: factory.config.Clock})
		registration, err := factory.optionalRegistration(collection.ProviderSalesforce, collection.CredentialSalesforceClient, version, client, err)
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		registrations = append(registrations, registration)
	}
	if version := factory.config.SaaSCollectorVersion; version != "" {
		// One collector for every registered platform. The platform and the
		// tenant arrive in the page request subject, and the credential is
		// the Nango connection reference, never a provider token.
		registry, err := saasplatforms.Registry()
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		api, err := saasdiscovery.NewCollectionAPI(saasdiscovery.CollectionAPIConfig{Registry: registry, Proxy: factory.config.SaaSProxy, Clock: factory.config.Clock})
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		client, err := saasdiscovery.NewCollectionClient(&discoveryBearerCollectionAPI{provider: collection.ProviderSaaS, saas: api, timeout: factory.config.ProviderTimeout}, factory.config.Artifacts, saasdiscovery.CollectionClientConfig{CollectorVersion: version, ParserVersion: factory.config.ParserVersion, ToolVersion: factory.config.ToolVersion, Clock: factory.config.Clock})
		registration, err := factory.optionalRegistration(collection.ProviderSaaS, collection.CredentialNangoConnection, version, client, err)
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		registrations = append(registrations, registration)
	}
	return newFirstPartyCollectionFactory(registrations)
}

// optionalRegistration is the registration of a provider a deployment serves
// only when it configures the provider's collector version.
func (factory *productionLiveDiscoveryCollectorFactory) optionalRegistration(provider collection.Provider, class collection.CredentialClass, version string, client collection.ProviderClient, clientErr error) (firstPartyProviderClientRegistration, error) {
	if clientErr != nil || nilWorkerDependency(client) {
		return firstPartyProviderClientRegistration{}, errRuntimeUnavailable
	}
	readiness, ok := client.(collection.ReadinessProbe)
	if !ok || nilWorkerDependency(readiness) {
		return firstPartyProviderClientRegistration{}, errRuntimeUnavailable
	}
	return firstPartyProviderClientRegistration{Provider: provider, CollectorVersion: version, CredentialClass: class, Client: client, Readiness: readiness, ReadinessTimeout: factory.config.ReadinessTimeout}, nil
}

func (factory *productionLiveDiscoveryCollectorFactory) collectorVersion(provider collection.Provider) string {
	if factory == nil {
		return ""
	}
	switch provider {
	case collection.ProviderAWS:
		return factory.config.AWSCollectorVersion
	case collection.ProviderKubernetes:
		return factory.config.KubernetesCollectorVersion
	case collection.ProviderGitHub:
		return factory.config.GitHubCollectorVersion
	case collection.ProviderOkta:
		return factory.config.OktaCollectorVersion
	case collection.ProviderMicrosoft:
		return factory.config.MicrosoftCollectorVersion
	case collection.ProviderSalesforce:
		return factory.config.SalesforceCollectorVersion
	case collection.ProviderSaaS:
		return factory.config.SaaSCollectorVersion
	default:
		return ""
	}
}

func validDiscoveryCIDRs(values []string) bool {
	if len(values) < 1 || len(values) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil || network.String() != value {
			return false
		}
		ones, bits := network.Mask.Size()
		if ones < 1 || bits != 32 && bits != 128 || bits == 32 && ones < 8 || bits == 128 && ones < 32 {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

var _ discoveryCollectorFactory = (*productionLiveDiscoveryCollectorFactory)(nil)

// discoveryAWSInventoryPageTimeout is the time one AWS inventory page may
// take. The provider timeout bounds a single request; a page makes one
// request per role, per attached policy and per region, each individually
// authorized, and cannot fit in a single request's budget. The value stays
// below the five minutes the workflow gives the page activity.
const discoveryAWSInventoryPageTimeout = 4 * time.Minute
