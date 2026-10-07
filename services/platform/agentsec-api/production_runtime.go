package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

type auditExportStorageFactory func(RuntimeConfig) ([]apiserver.AuditExportStorageConfiguration, *http.Transport, error)
type complianceStorageFactory func(RuntimeConfig) (complianceStorageResources, error)

func buildRuntimeDependencies(ctx context.Context, config RuntimeConfig) (RuntimeDependencies, error) {
	return buildRuntimeDependenciesWithAuditExportStorage(ctx, config, newAuditExportStorageClients)
}

func buildRuntimeDependenciesWithAuditExportStorage(ctx context.Context, config RuntimeConfig, factory auditExportStorageFactory) (RuntimeDependencies, error) {
	return buildRuntimeDependenciesWithStorage(ctx, config, factory, newComplianceStorageResources)
}

func buildRuntimeDependenciesWithStorage(ctx context.Context, config RuntimeConfig, factory auditExportStorageFactory, complianceFactory complianceStorageFactory) (RuntimeDependencies, error) {
	return buildRuntimeDependenciesWithReadinessTransport(ctx, config, factory, complianceFactory, nil)
}

func buildRuntimeDependenciesWithReadinessTransport(ctx context.Context, config RuntimeConfig, factory auditExportStorageFactory, complianceFactory complianceStorageFactory, readinessTransport http.RoundTripper) (RuntimeDependencies, error) {
	dependencies, err := buildRuntimeDependenciesWithReadinessTransportDiagnostic(ctx, config, factory, complianceFactory, readinessTransport)
	return dependencies, runtimeDependencyPublicError(err)
}

func buildRuntimeDependenciesWithReadinessTransportDiagnostic(ctx context.Context, config RuntimeConfig, factory auditExportStorageFactory, complianceFactory complianceStorageFactory, readinessTransport http.RoundTripper) (RuntimeDependencies, error) {
	if ctx == nil || ctx.Err() != nil || factory == nil || complianceFactory == nil || !validRuntimeConfig(config) || !config.RuntimeServices.Enabled {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("runtime-inputs", errRuntimeUnavailable)
	}
	connectCtx, cancel := context.WithTimeout(ctx, config.ProviderTimeout)
	defer cancel()
	database, pool, err := openRuntimePostgres(connectCtx, config.PostgresDSN, config.ProviderTimeout)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("core-postgres", errRuntimeUnavailable)
	}
	securityAgentDatabase, securityAgentPool, err := openRuntimePostgres(connectCtx, config.SecurityAgentPostgresDSN, config.ProviderTimeout)
	if err != nil {
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("security-agent-postgres", errRuntimeUnavailable)
	}
	services, err := runtimeservices.Connect(ctx, config.RuntimeServices)
	if err != nil || services == nil {
		_ = securityAgentDatabase.Close()
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("native-services", errRuntimeUnavailable)
	}
	keepServices := false
	defer func() {
		if !keepServices {
			_ = services.Close()
		}
	}()
	if database.RequireCurrentAuthorization() != nil || securityAgentDatabase.RequireCurrentAuthorization() != nil {
		_ = securityAgentDatabase.Close()
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("current-authorization", errRuntimeUnavailable)
	}
	checker, checkerErr := authorization.NewOpenFGA(services.FGA, config.RuntimeServices)
	revisions, revisionErr := authorization.NewCurrentProjectionRepository(ctx, pool, config.RuntimeServices.ApprovalMaintenanceProfileChecksum)
	resolver, resolverErr := apiserver.NewPostgresAuthorizationResolverWithSecurityAgent(database, securityAgentDatabase)
	attestationKey, attestationErr := authorization.NewAttestationKey([]byte(config.WorkflowSigningKey))
	if checkerErr != nil || revisionErr != nil || resolverErr != nil || attestationErr != nil {
		_ = securityAgentDatabase.Close()
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("authorization-components", errRuntimeUnavailable)
	}
	if err := checkAuthorizationRuntimeReadyWithinTimeout(ctx, database, securityAgentDatabase, attestationKey.Version(), config.ProviderTimeout); err != nil {
		_ = securityAgentDatabase.Close()
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("authorization-readiness", errRuntimeUnavailable)
	}
	authorizer := &apiserver.OpenFGAAuthorizer{Reader: revisions, Checker: checker, Resolver: resolver, StoreID: config.RuntimeServices.StoreID, ModelID: config.RuntimeServices.ModelID, AttestationKey: attestationKey}
	authenticator, err := apiserver.NewStytchOAuthAuthenticator(config.StytchBaseURL, config.StytchProjectID, config.StytchSecret, config.ProviderTimeout, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	if err != nil {
		_ = securityAgentDatabase.Close()
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("identity-authenticator", errRuntimeUnavailable)
	}
	repository, err := apiserver.NewPostgresRepository(database)
	if err != nil {
		_ = securityAgentDatabase.Close()
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("identity-repository", errRuntimeUnavailable)
	}
	provider, err := apiserver.NewRepositoryIdentityProviderWithStart(authenticator, repository, repository, config.StytchAuthorizeURL, config.StytchPublicToken, config.StytchOrganizationID, config.PublicOrigin+"/auth/callback")
	if err == nil {
		err = provider.RequireNativeIdentity([]byte(config.WorkflowSigningKey), runtimeIdentityDeployment(config))
	}
	if err != nil {
		_ = securityAgentDatabase.Close()
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("native-identity-provider", errRuntimeUnavailable)
	}
	observer, observerErr := orchestration.NewSingleTestOriginalObserver(services.Temporal, 5*time.Second)
	if observerErr != nil {
		_ = securityAgentDatabase.Close()
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("temporal-observer", errRuntimeUnavailable)
	}
	dependencies, err := composeRuntimeDependenciesWithRecoveryDiagnostic(ctx, config, database, securityAgentDatabase, provider, factory, complianceFactory, os.Stdout, readinessTransport, observer, authorizer)
	if err != nil {
		_ = securityAgentDatabase.Close()
		_ = database.Close()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("composition", err)
	}
	dependencies.Closers = append(dependencies.Closers, securityAgentDatabase, database)
	if services != nil {
		previous := dependencies.ReadinessCheck
		dependencies.ReadinessCheck = authorizationRuntimeReadiness(services.Ready, previous, database, securityAgentDatabase, attestationKey.Version(), config.RuntimeServices.Timeout)
		dependencies.Closers = append(dependencies.Closers, services)
	}
	keepServices = true
	dependencies.Metrics.poolStats = func() poolSaturation {
		core := pool.Stat()
		securityAgent := securityAgentPool.Stat()
		return poolSaturation{Acquired: core.AcquiredConns() + securityAgent.AcquiredConns(), Idle: core.IdleConns() + securityAgent.IdleConns(), Maximum: core.MaxConns() + securityAgent.MaxConns()}
	}
	return dependencies, nil
}

func openRuntimePostgres(ctx context.Context, dsn string, healthCheckPeriod time.Duration) (*apiserver.PostgresJSONDatabase, *pgxpool.Pool, error) {
	poolConfig, err := runtimepostgres.ParsePoolConfig(dsn)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	poolConfig.MaxConns = 20
	poolConfig.MinConns = 2
	poolConfig.HealthCheckPeriod = healthCheckPeriod
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, errRuntimeUnavailable
	}
	database, err := apiserver.NewPostgresJSONDatabase(&pgxProductionDriver{pool: pool})
	if err != nil {
		pool.Close()
		return nil, nil, errRuntimeUnavailable
	}
	return database, pool, nil
}

func composeRuntimeDependencies(config RuntimeConfig, database apiserver.JSONDatabase, provider apiserver.CallbackProvider) (RuntimeDependencies, error) {
	return composeRuntimeDependenciesWithSecurityAgent(config, database, nil, provider)
}

func composeRuntimeDependenciesWithSecurityAgent(config RuntimeConfig, database, securityAgentDatabase apiserver.JSONDatabase, provider apiserver.CallbackProvider) (RuntimeDependencies, error) {
	return composeRuntimeDependenciesWithContext(context.Background(), config, database, securityAgentDatabase, provider)
}

func composeRuntimeDependenciesWithContext(ctx context.Context, config RuntimeConfig, database, securityAgentDatabase apiserver.JSONDatabase, provider apiserver.CallbackProvider) (RuntimeDependencies, error) {
	return composeRuntimeDependenciesWithAuditExportStorage(ctx, config, database, securityAgentDatabase, provider, newAuditExportStorageClients)
}

func composeRuntimeDependenciesWithAuditExportStorage(ctx context.Context, config RuntimeConfig, database, securityAgentDatabase apiserver.JSONDatabase, provider apiserver.CallbackProvider, factory auditExportStorageFactory) (RuntimeDependencies, error) {
	return composeRuntimeDependenciesWithStorage(ctx, config, database, securityAgentDatabase, provider, factory, newComplianceStorageResources)
}

func composeRuntimeDependenciesWithStorage(ctx context.Context, config RuntimeConfig, database, securityAgentDatabase apiserver.JSONDatabase, provider apiserver.CallbackProvider, factory auditExportStorageFactory, complianceFactory complianceStorageFactory) (RuntimeDependencies, error) {
	return composeRuntimeDependenciesWithTelemetry(ctx, config, database, securityAgentDatabase, provider, factory, complianceFactory, os.Stdout)
}

func composeRuntimeDependenciesWithTelemetry(ctx context.Context, config RuntimeConfig, database, securityAgentDatabase apiserver.JSONDatabase, provider apiserver.CallbackProvider, factory auditExportStorageFactory, complianceFactory complianceStorageFactory, output io.Writer) (RuntimeDependencies, error) {
	return composeRuntimeDependenciesWithReadinessTransport(ctx, config, database, securityAgentDatabase, provider, factory, complianceFactory, output, nil)
}

func composeRuntimeDependenciesWithReadinessTransport(ctx context.Context, config RuntimeConfig, database, securityAgentDatabase apiserver.JSONDatabase, provider apiserver.CallbackProvider, factory auditExportStorageFactory, complianceFactory complianceStorageFactory, output io.Writer, readinessTransport http.RoundTripper, authorizers ...apiserver.RequestAuthorizer) (RuntimeDependencies, error) {
	return composeRuntimeDependenciesWithRecovery(ctx, config, database, securityAgentDatabase, provider, factory, complianceFactory, output, readinessTransport, nil, authorizers...)
}

func composeRuntimeDependenciesWithRecovery(ctx context.Context, config RuntimeConfig, database, securityAgentDatabase apiserver.JSONDatabase, provider apiserver.CallbackProvider, factory auditExportStorageFactory, complianceFactory complianceStorageFactory, output io.Writer, readinessTransport http.RoundTripper, observer orchestration.SingleTestOriginalObserver, authorizers ...apiserver.RequestAuthorizer) (RuntimeDependencies, error) {
	dependencies, err := composeRuntimeDependenciesWithRecoveryDiagnostic(ctx, config, database, securityAgentDatabase, provider, factory, complianceFactory, output, readinessTransport, observer, authorizers...)
	return dependencies, runtimeDependencyPublicError(err)
}

func composeRuntimeDependenciesWithRecoveryDiagnostic(ctx context.Context, config RuntimeConfig, database, securityAgentDatabase apiserver.JSONDatabase, provider apiserver.CallbackProvider, factory auditExportStorageFactory, complianceFactory complianceStorageFactory, output io.Writer, readinessTransport http.RoundTripper, observer orchestration.SingleTestOriginalObserver, authorizers ...apiserver.RequestAuthorizer) (RuntimeDependencies, error) {
	if ctx == nil || ctx.Err() != nil || factory == nil || complianceFactory == nil || invalidRuntimeValue(output) || !validRuntimeConfig(config) {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("composition-inputs", errRuntimeUnavailable)
	}
	var authorizer apiserver.RequestAuthorizer
	if len(authorizers) > 1 {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("composition-authorization", errRuntimeUnavailable)
	}
	if len(authorizers) == 1 {
		authorizer = authorizers[0]
	}
	currentRequired := func(db apiserver.JSONDatabase) bool {
		current, ok := db.(interface{ CurrentAuthorizationRequired() bool })
		return ok && current.CurrentAuthorizationRequired()
	}
	if config.RuntimeServices.Enabled || currentRequired(database) || currentRequired(securityAgentDatabase) || !invalidRuntimeValue(authorizer) {
		if !config.RuntimeServices.Enabled || invalidRuntimeValue(authorizer) || !currentRequired(database) || !currentRequired(securityAgentDatabase) {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("composition-authorization", errRuntimeUnavailable)
		}
	}
	if config.EvidenceExportWorkflow == "enabled" && (config.ComplianceExports == nil || invalidRuntimeValue(securityAgentDatabase)) {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("composition-authorization", errRuntimeUnavailable)
	}
	metrics := newOperationalMetrics()
	exporter := newStructuredSpanExporter(output)
	tracedDatabase := &tracedJSONDatabase{next: database, metrics: metrics, exporter: exporter}
	var securityAgentRepository *apiserver.PostgresRepository
	var approvalNotificationRepository *apiserver.PostgresRepository
	var tracedSecurityAgentDatabase *tracedJSONDatabase
	if !invalidRuntimeValue(securityAgentDatabase) {
		tracedSecurityAgentDatabase = &tracedJSONDatabase{next: securityAgentDatabase, metrics: metrics, exporter: exporter}
		if config.AttackLabWorkflow == "enabled" {
			tracedSecurityAgentDatabase.attackLabReady = newAttackLabWorkflowReadiness(readinessTransport)
		}
		var securityAgentErr error
		securityAgentRepository, securityAgentErr = apiserver.NewSecurityAgentPostgresRepository(tracedSecurityAgentDatabase)
		if securityAgentErr != nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("security-agent-repositories", errRuntimeUnavailable)
		}
		approvalNotificationRepository, securityAgentErr = apiserver.NewApprovalNotificationPostgresRepository(tracedSecurityAgentDatabase)
		if securityAgentErr != nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("security-agent-repositories", errRuntimeUnavailable)
		}
	}
	tracedProvider := &tracedCallbackProvider{next: provider, metrics: metrics, exporter: exporter}
	policyHistory, err := newProductionPolicyHistory(config)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("policy-history", errRuntimeUnavailable)
	}
	searchResourcesOwned := true
	defer func() {
		if searchResourcesOwned {
			_ = policyHistory.Close()
		}
	}()
	repository, err := apiserver.NewPostgresRepositoryWithRuntimeSessionSearchIndex(tracedDatabase, policyHistory.sessionSearch, config.RuntimeSessionIndex)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("core-repositories", errRuntimeUnavailable)
	}
	connectorRepository, err := apiserver.NewConnectorRepository(tracedDatabase)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("core-repositories", errRuntimeUnavailable)
	}
	referenceRepository, err := apiserver.NewReferenceAuthorizationRepository(tracedDatabase)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("core-repositories", errRuntimeUnavailable)
	}
	secretsClient, secretsTransport, err := newConnectorSecretsClient(config)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-secrets", errRuntimeUnavailable)
	}
	secretsDriver := &connectorSecretsDriver{client: secretsClient}
	ticketSecrets, err := newFindingTicketSecretResolver(secretsDriver, config.ConnectorSecretPrefix, config.ProviderTimeout)
	if err != nil {
		secretsTransport.CloseIdleConnections()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("ticket-services", errRuntimeUnavailable)
	}
	ticketWebhook, err := apiserver.NewProductionFindingTicketWebhook(config.FindingTicketEgressCIDRs, config.ProviderTimeout)
	if err != nil {
		secretsTransport.CloseIdleConnections()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("ticket-services", errRuntimeUnavailable)
	}
	ticketService, err := apiserver.NewFindingTicketService(apiserver.FindingTicketServiceConfig{
		Repository:   repository,
		Secrets:      ticketSecrets,
		Webhook:      ticketWebhook,
		LeaseSeconds: 15,
		NewDeliveryID: func(domain.Scope, string) (string, error) {
			return newFindingTicketDeliveryID()
		},
		NewLeaseToken: newFindingTicketLeaseToken,
	})
	if err != nil {
		secretsTransport.CloseIdleConnections()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("ticket-services", errRuntimeUnavailable)
	}
	webhookTestService, err := apiserver.NewIntegrationWebhookTestService(apiserver.IntegrationWebhookTestServiceConfig{
		Repository: repository, Secrets: ticketSecrets, Webhook: ticketWebhook, LeaseSeconds: 15,
		NewDeliveryID: func(scope domain.Scope, integrationID string) (string, error) { return newFindingTicketDeliveryID() },
		NewLeaseToken: newFindingTicketLeaseToken,
	})
	if err != nil {
		secretsTransport.CloseIdleConnections()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("ticket-services", errRuntimeUnavailable)
	}
	secretStore, err := apiserver.NewDurableOAuthSecretStore(secretsDriver, config.ConnectorSecretPrefix, config.ConnectorKMSKeyARN, config.ProviderTimeout, func() time.Time { return time.Now().UTC() })
	if err != nil {
		secretsTransport.CloseIdleConnections()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-oauth", errRuntimeUnavailable)
	}
	providerHTTP, err := newConnectorHTTPClient(config.ProviderTimeout)
	if err != nil {
		secretsTransport.CloseIdleConnections()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-oauth", errRuntimeUnavailable)
	}
	providerTransport, ok := providerHTTP.Transport.(*http.Transport)
	if !ok {
		secretsTransport.CloseIdleConnections()
		providerHTTP.CloseIdleConnections()
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-oauth", errRuntimeUnavailable)
	}
	connectorResources := []io.Closer{transportCloser{secretsTransport}, transportCloser{providerTransport}}
	keepConnectorResources := false
	defer func() {
		if !keepConnectorResources {
			for _, closer := range connectorResources {
				_ = closer.Close()
			}
		}
	}()
	var auditExports apiserver.AuditExportProductionHandler
	var compliance apiserver.ComplianceProductionHandler
	var agentExports apiserver.SecurityAgentExportProductionHandler
	if config.ComplianceExports != nil {
		resources, complianceErr := complianceFactory(config)
		if resources.transport != nil {
			connectorResources = append(connectorResources, transportCloser{resources.transport})
		}
		if complianceErr != nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("compliance-export", errRuntimeUnavailable)
		}
		resources.config.CursorSigningKey = []byte(config.WorkflowSigningKey)
		compliance, complianceErr = apiserver.NewComplianceProductionHandler(ctx, tracedDatabase, resources.config)
		if complianceErr != nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("compliance-export", errRuntimeUnavailable)
		}
		if tracedSecurityAgentDatabase != nil {
			agentExports, complianceErr = apiserver.NewSecurityAgentExportProductionHandler(ctx, tracedSecurityAgentDatabase, resources.config)
			if complianceErr != nil {
				return RuntimeDependencies{}, markRuntimeDependencyFailure("compliance-export", errRuntimeUnavailable)
			}
			if config.EvidenceExportWorkflow == "enabled" && !invalidRuntimeValue(agentExports) {
				tracedSecurityAgentDatabase.exportReady = newExportWorkflowReadiness(readinessTransport)
			}
		}
	}
	var auditPublicPages *apiserver.AuditPublicPageRepository
	if config.AuditExports != nil {
		entries, transport, exportErr := factory(config)
		if transport != nil {
			connectorResources = append(connectorResources, transportCloser{transport})
		}
		if exportErr != nil || transport == nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("audit-export", errRuntimeUnavailable)
		}
		exportContext, cancel := context.WithTimeout(ctx, config.ProviderTimeout)
		auditExports, exportErr = apiserver.NewAuditExportProductionHandler(exportContext, tracedDatabase, apiserver.AuditExportHandlerConfiguration{Storage: entries, CursorSigningKey: config.AuditExports.CursorSigningKey, ProviderTimeout: config.ProviderTimeout})
		cancel()
		if exportErr != nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("audit-export", errRuntimeUnavailable)
		}
		auditPublicPages, exportErr = apiserver.NewAuditPublicPageRepository(ctx, tracedDatabase)
		if exportErr != nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("audit-export", errRuntimeUnavailable)
		}
	}
	providerSecrets := &connectorProviderSecrets{driver: secretsDriver, root: strings.TrimSuffix(config.ConnectorSecretPrefix, "/oauth"), kmsKey: config.ConnectorKMSKeyARN}
	githubAdapter, err := githubdiscovery.NewAdapter(githubdiscovery.Config{ClientID: config.GitHubClientID, ClientSecretReference: config.GitHubSecretReference, CallbackURL: config.PublicOrigin + "/api/v1/integrations/oauth/callback"}, &githubExchangeClient{http: providerHTTP, secrets: providerSecrets, appID: config.GitHubAppID, privateKeyReference: config.GitHubPrivateKeyReference}, config.ProviderTimeout)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-providers", errRuntimeUnavailable)
	}
	connectorProviders := map[string]apiserver.ConnectorOAuthProviderDefinition{
		"github": {Provider: &githubOAuthProvider{adapter: githubAdapter}, RequestedScopes: []string{"actions:read", "contents:read", "metadata:read"}, CredentialClass: "github_installation_reference"},
		"okta":   {Factory: &oktaOAuthFactory{clientID: config.OktaClientID, secretReference: config.OktaSecretReference, callback: config.PublicOrigin + "/api/v1/integrations/oauth/callback", exchange: &oktaExchangeClient{http: providerHTTP, secrets: providerSecrets}, timeout: config.ProviderTimeout}, RequestedScopes: []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}, CredentialClass: "okta_refresh_reference"},
	}
	connectorChecks := map[string]apiserver.ConnectorCapabilityCheck{
		"github": func(ctx context.Context) error {
			return errors.Join(providerSecrets.ready(ctx, config.GitHubSecretReference), providerSecrets.ready(ctx, config.GitHubPrivateKeyReference))
		},
		"okta": func(ctx context.Context) error { return providerSecrets.ready(ctx, config.OktaSecretReference) },
	}
	nangoSecrets, err := newNangoServiceSecretResolver("/var/run/secrets/zasp-nango/service-key")
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-providers", errRuntimeUnavailable)
	}
	nangoCloser, err := addProductionNangoProvider(config, nangoSecrets, connectorProviders, connectorChecks)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-providers", errRuntimeUnavailable)
	}
	if nangoCloser != nil {
		connectorResources = append(connectorResources, nangoCloser)
	}
	connectorRegistry, err := apiserver.NewConnectorProviderRegistry(connectorProviders, connectorChecks)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-providers", errRuntimeUnavailable)
	}
	connectorHandler, err := apiserver.NewConnectorHTTPHandler(apiserver.ConnectorHTTPConfig{
		Repository: connectorRepository, Workflows: repository, Secrets: secretStore, Clock: func() time.Time { return time.Now().UTC() }, Registry: connectorRegistry,
	})
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-providers", errRuntimeUnavailable)
	}
	referenceResolver := &referenceSecretResolver{driver: secretsDriver, root: strings.TrimSuffix(config.ConnectorSecretPrefix, "/oauth")}
	referenceAWSClient, referenceAWSTransport, err := newReferenceAWSClient(config)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("reference-providers", errRuntimeUnavailable)
	}
	connectorResources = append(connectorResources, transportCloser{referenceAWSTransport})
	awsAdapter, err := awsdiscovery.NewAdapter(referenceAWSClient, referenceResolver, config.ProviderTimeout)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("reference-providers", errRuntimeUnavailable)
	}
	referenceProbes := map[string]apiserver.ReferenceAuthorizationProbe{"aws": &awsReferenceProbe{adapter: awsAdapter}}
	referenceChecks := map[string]apiserver.ConnectorCapabilityCheck{"aws": func(context.Context) error { return nil }}
	if len(config.KubernetesEgressCIDRs) > 0 {
		cidrs, cidrErr := parseReferenceCIDRs(config.KubernetesEgressCIDRs)
		if cidrErr != nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("reference-providers", errRuntimeUnavailable)
		}
		probeClient := &kubernetesProbeClient{resolver: referenceResolver, cidrs: cidrs, lookup: net.DefaultResolver.LookupIPAddr, timeout: config.ProviderTimeout}
		kubernetesAdapter, adapterErr := kubernetesdiscovery.NewAdapter(probeClient, config.ProviderTimeout)
		if adapterErr != nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("reference-providers", errRuntimeUnavailable)
		}
		referenceProbes["kubernetes"] = &kubernetesReferenceProbe{adapter: kubernetesAdapter, resolver: referenceResolver}
		referenceChecks["kubernetes"] = func(context.Context) error { return nil }
	}
	referenceRegistry, err := apiserver.NewReferenceConnectorRegistry(referenceProbes, referenceChecks)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("reference-providers", errRuntimeUnavailable)
	}
	referenceHandler, err := apiserver.NewReferenceAuthorizationHTTPHandler(apiserver.ReferenceAuthorizationHTTPConfig{Repository: referenceRepository, Workflows: repository, Registry: referenceRegistry})
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("reference-providers", errRuntimeUnavailable)
	}
	connectorSurface, err := apiserver.NewConnectorSurfaceHandler(connectorHandler, referenceHandler)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("reference-providers", errRuntimeUnavailable)
	}
	workerOwner, err := newConnectorWorkerOwner(os.Getenv("HOSTNAME"), rand.Reader)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-lifecycle", errRuntimeUnavailable)
	}
	connectorReconciler, err := apiserver.NewConnectorReconciler(apiserver.ConnectorReconcilerConfig{Repository: connectorRepository, Workflows: repository, Registry: connectorRegistry, Secrets: secretStore, Owner: workerOwner, LeaseSeconds: 30, Limit: 25, Interval: time.Second})
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-lifecycle", errRuntimeUnavailable)
	}
	lifecycleWorkers := []func(context.Context) error{connectorReconciler.Run, func(ctx context.Context) error {
		return runReconciliationMaintenance(ctx, connectorRepository, metrics)
	}}
	var approvalNotificationReconciler approvalNotificationLifecycle
	if approvalNotificationRepository != nil {
		var closer io.Closer
		approvalNotificationReconciler, closer, err = selectApprovalNotificationLifecycle(config,
			func() (approvalNotificationLifecycle, io.Closer, error) {
				return newRuntimeApprovalMaintenance(ctx, config, authorizer, ticketSecrets, ticketWebhook, workerOwner)
			},
			func() (approvalNotificationLifecycle, io.Closer, error) {
				r, e := apiserver.NewApprovalNotificationReconciler(apiserver.ApprovalNotificationReconcilerConfig{Repository: approvalNotificationRepository, Secrets: ticketSecrets, Webhook: ticketWebhook, Owner: workerOwner, LeaseSeconds: 30, Interval: time.Second, NewLeaseToken: newFindingTicketLeaseToken})
				return r, nil, e
			})
		if closer != nil {
			connectorResources = append(connectorResources, closer)
		}
		if err != nil {
			return RuntimeDependencies{}, markRuntimeDependencyFailure("connector-lifecycle", errRuntimeUnavailable)
		}
		lifecycleWorkers = append(lifecycleWorkers, approvalNotificationReconciler.Run)
	}
	cookie := apiserver.CookiePolicy{Secure: config.CookieSecure, WorkflowSigningKey: []byte(config.WorkflowSigningKey), TokenRevealKey: config.TokenRevealKey, Clock: func() time.Time { return time.Now().UTC().Truncate(time.Second) }, BuildVersion: buildVersion, DeploymentMode: config.DeploymentMode, OrganizationID: config.OrganizationID, DiscoveryParserVersion: config.DiscoveryParserVersion, DiscoveryToolVersion: config.DiscoveryToolVersion, ConnectorCapabilities: apiserver.CombinedConnectorCapabilities{OAuth: connectorRegistry, Reference: referenceRegistry}, FindingTickets: ticketService, IntegrationWebhookTests: webhookTestService}
	cookie.SecurityAgentOrderedHTTPEnabled = config.SecurityAgentOrderedHTTPEnabled
	cookie.AuditPublicPages = auditPublicPages
	if verifier, ok := securityAgentDatabase.(interface {
		SingleTestRecoveryAvailable(context.Context) (bool, error)
	}); ok {
		cookie.SingleTestRecoveryReady = verifier.SingleTestRecoveryAvailable
		cookie.SingleTestOriginalObserver = observer
	} else if currentRequired(securityAgentDatabase) {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("production-handlers", errRuntimeUnavailable)
	}
	var handlers apiserver.Dependencies
	var authenticate apiserver.Authenticator
	if securityAgentRepository != nil {
		handlers, authenticate, err = apiserver.NewProductionHandlersWithSecurityAgent(repository, securityAgentRepository, tracedProvider, connectorSurface, cookie)
	} else {
		handlers, authenticate, err = apiserver.NewProductionHandlers(repository, tracedProvider, connectorSurface, cookie)
	}
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("production-handlers", errRuntimeUnavailable)
	}
	connectorResources = append(connectorResources, policyHistory)
	searchResourcesOwned = false // The existing connector-resource cleanup now owns it.
	policyDecisions, err := apiserver.NewPolicyDecisionRepository(tracedDatabase)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("policy-surface", errRuntimeUnavailable)
	}
	policyHandler, err := apiserver.NewPolicyPublicHTTPHandler(apiserver.PolicyPublicHTTPConfig{Workflows: repository, History: policyHistory, Decisions: policyDecisions})
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("policy-surface", errRuntimeUnavailable)
	}
	handlers.Workflow, err = apiserver.NewPolicyWorkflowSurface(handlers.Workflow, policyHandler)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("policy-surface", errRuntimeUnavailable)
	}
	var composition http.Handler
	handlers.Authorizer = authorizer
	if agentExports != nil {
		composition, err = apiserver.NewCompositionWithSecurityAgentExports(handlers, auditExports, compliance, agentExports)
	} else if compliance != nil {
		composition, err = apiserver.NewCompositionWithCompliance(handlers, auditExports, compliance)
	} else if auditExports != nil {
		composition, err = apiserver.NewCompositionWithAuditExports(handlers, auditExports)
	} else {
		composition, err = apiserver.NewComposition(handlers)
	}
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("handler-composition", errRuntimeUnavailable)
	}
	product, err := apiserver.NewProductMiddleware(apiserver.ProductSecurity{
		PublicOrigin: config.PublicOrigin, MaximumBodyBytes: 16 * 1024, Authenticate: authenticate, GenerateCorrelationID: generateCorrelationID,
	}, composition)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("product-middleware", errRuntimeUnavailable)
	}
	var stytchWebhook http.Handler
	if currentRequired(database) {
		stytchWebhook, err = apiserver.NewProductionNativeStytchWebhookHandler(repository, config.StytchWebhookSecret, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }, []byte(config.WorkflowSigningKey), runtimeIdentityDeployment(config))
	} else {
		// This explicit legacy composition is unavailable from the production
		// builder, which requires current authorization on both databases.
		stytchWebhook, err = apiserver.NewProductionStytchWebhookHandler(repository, config.StytchProjectID, config.StytchWebhookSecret, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	}
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("identity-webhook", errRuntimeUnavailable)
	}
	publicSurface, err := mountPublicSurface(product, stytchWebhook)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("public-surface", errRuntimeUnavailable)
	}
	operational, err := newOperationalMiddleware(output, metrics, newRequestLimiter(config.RequestRatePerSecond, config.RequestBurst, 10000, time.Now), config.RequestTimeout, exporter, publicSurface)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("operational-middleware", errRuntimeUnavailable)
	}
	edge, err := newEdgeSecurityMiddleware(edgeSecurityConfig{PublicOrigin: config.PublicOrigin, TrustedProxyCIDRs: config.TrustedProxyCIDRs}, operational)
	if err != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("edge-middleware", errRuntimeUnavailable)
	}
	if ctx.Err() != nil {
		return RuntimeDependencies{}, markRuntimeDependencyFailure("construction-context", errRuntimeUnavailable)
	}
	stores := []StoreDependency{{Name: "postgres-core", Durable: true}, {Name: "postgres-security-agent", Durable: true}, {Name: "aws-secrets-manager-oauth", Durable: true}, {Name: "aws-secrets-manager-webhook", Durable: true}, {Name: "opensearch-runtime-policy-history", Durable: true}}
	if compliance != nil {
		stores = append(stores, StoreDependency{Name: "aws-s3-compliance-exports", Durable: true})
	}
	if auditExports != nil {
		stores = append(stores, StoreDependency{Name: "aws-s3-audit-exports", Durable: true})
	}
	keepConnectorResources = true
	return RuntimeDependencies{ProductHandler: edge, Metrics: metrics, LifecycleWorker: func(ctx context.Context) error { return runLifecycleWorkers(ctx, lifecycleWorkers...) }, ReadinessCheck: func(ctx context.Context) error {
		if currentRequired(database) && currentRequired(securityAgentDatabase) {
			checks := []func(context.Context) error{repository.Ready, connectorRepository.Ready, referenceRepository.Ready, policyHandler.Ready, tracedProvider.Ready}
			if agentExports != nil {
				checks = append(checks, agentExports.Ready)
			}
			if compliance != nil {
				checks = append(checks, compliance.Ready)
			}
			if auditExports != nil {
				checks = append(checks, auditExports.Ready)
			}
			if securityAgentRepository != nil {
				checks = append(checks, securityAgentRepository.Ready)
			}
			if approvalNotificationRepository != nil {
				checks = append(checks, func(probe context.Context) error {
					if err := approvalNotificationLifecycleReady(probe, approvalNotificationRepository.ReadyApprovalNotifications, approvalNotificationReconciler); err != nil {
						return errRuntimeUnavailable
					}
					return nil
				})
			}
			return currentComponentReadiness(ctx, connectorReconciler.Ready, checks...)
		}

		if agentExports != nil {
			if err := agentExports.Ready(ctx); err != nil {
				return errRuntimeUnavailable
			}
		}
		if compliance != nil {
			if err := compliance.Ready(ctx); err != nil {
				return errRuntimeUnavailable
			}
		}
		if auditExports != nil {
			if err := auditExports.Ready(ctx); err != nil {
				return errRuntimeUnavailable
			}
		}
		if err := repository.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if securityAgentRepository != nil {
			if err := securityAgentRepository.Ready(ctx); err != nil {
				return errRuntimeUnavailable
			}
		}
		if approvalNotificationRepository != nil {
			if err := approvalNotificationLifecycleReady(ctx, approvalNotificationRepository.ReadyApprovalNotifications, approvalNotificationReconciler); err != nil {
				return errRuntimeUnavailable
			}
		}
		if err := connectorRepository.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if err := referenceRepository.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if err := policyHandler.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if err := tracedProvider.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if !connectorReconciler.Ready() {
			return errRuntimeUnavailable
		}
		return nil
	}, Stores: stores, Closers: connectorResources}, nil
}

func mountPublicSurface(product, stytchWebhook http.Handler) (http.Handler, error) {
	if product == nil || stytchWebhook == nil {
		return nil, errRuntimeUnavailable
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request != nil && request.URL != nil && request.URL.Path == "/api/v1/webhooks/stytch" {
			stytchWebhook.ServeHTTP(writer, request)
			return
		}
		product.ServeHTTP(writer, request)
	}), nil
}

func newConnectorWorkerOwner(hostname string, source io.Reader) (string, error) {
	if len(hostname) < 1 || len(hostname) > 96 || strings.TrimSpace(hostname) != hostname || strings.ContainsAny(hostname, "\x00\r\n") || source == nil {
		return "", errRuntimeUnavailable
	}
	random := make([]byte, 8)
	if _, err := io.ReadFull(source, random); err != nil {
		return "", errRuntimeUnavailable
	}
	return "agentsec-api:" + hostname + ":" + hex.EncodeToString(random), nil
}

type transportCloser struct{ transport *http.Transport }

func (closer transportCloser) Close() error {
	if closer.transport != nil {
		closer.transport.CloseIdleConnections()
	}
	return nil
}

type tracedJSONDatabase struct {
	exportReady    func(context.Context) bool
	next           apiserver.JSONDatabase
	metrics        *operationalMetrics
	exporter       operationalSpanExporter
	attackLabReady func(context.Context) bool
}

func (database *tracedJSONDatabase) NativeIdentityDatabase() *apiserver.PostgresJSONDatabase {
	if database == nil {
		return nil
	}
	native, ok := database.next.(*apiserver.PostgresJSONDatabase)
	if !ok || !native.CurrentAuthorizationRequired() {
		return nil
	}
	return native
}

func (database *tracedJSONDatabase) CurrentAuthorizationRequired() bool {
	current, ok := database.next.(interface{ CurrentAuthorizationRequired() bool })
	return ok && current.CurrentAuthorizationRequired()
}

func (database *tracedJSONDatabase) ActivateCurrentTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, error) {
	if database == nil || invalidRuntimeValue(database.next) {
		return nil, apiserver.ErrRepositoryUnavailable
	}
	current, ok := database.next.(interface {
		ActivateCurrentTemporalTestDefinition(context.Context, ...any) (json.RawMessage, error)
	})
	if !ok {
		return nil, apiserver.ErrRepositoryUnavailable
	}
	return current.ActivateCurrentTemporalTestDefinition(ctx, args...)
}

func (database *tracedJSONDatabase) CurrentAuthorizationSourceReady(ctx context.Context, version int, checksum, fingerprint string) (bool, error) {
	current, ok := database.next.(interface {
		CurrentAuthorizationSourceReady(context.Context, int, string, string) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return current.CurrentAuthorizationSourceReady(ctx, version, checksum, fingerprint)
}

func (database *tracedJSONDatabase) SecurityAgentExportsAvailable(ctx context.Context) (bool, error) {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil || ctx.Err() != nil {
		return false, apiserver.ErrRepositoryUnavailable
	}
	capability, ok := database.next.(interface {
		SecurityAgentExportsAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return capability.SecurityAgentExportsAvailable(ctx)
}

func (database *tracedJSONDatabase) SecurityAgentAttackLabAvailable(ctx context.Context) (bool, error) {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil || ctx.Err() != nil {
		return false, apiserver.ErrRepositoryUnavailable
	}
	capability, ok := database.next.(interface {
		SecurityAgentAttackLabAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return capability.SecurityAgentAttackLabAvailable(ctx)
}

func (database *tracedJSONDatabase) TemporalAdmissionAvailable(ctx context.Context) (bool, error) {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil || ctx.Err() != nil {
		return false, apiserver.ErrRepositoryUnavailable
	}
	capability, ok := database.next.(interface {
		TemporalAdmissionAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return capability.TemporalAdmissionAvailable(ctx)
}

func (database *tracedJSONDatabase) SecurityAgentAttackLabWorkflowAvailable(ctx context.Context) (bool, error) {
	installed, err := database.SecurityAgentAttackLabAvailable(ctx)
	if err != nil || !installed {
		return false, err
	}
	if database.attackLabReady == nil {
		return false, nil
	}
	return database.attackLabReady(ctx), nil
}

// Keep optional authority visible through the production decorator. Legacy
// adapters without these capabilities retain their previous behavior.
func (database *tracedJSONDatabase) SecurityAgentExistingTestDefinitionsAvailable(ctx context.Context) (bool, error) {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil || ctx.Err() != nil {
		return false, apiserver.ErrRepositoryUnavailable
	}
	capability, ok := database.next.(interface {
		SecurityAgentExistingTestDefinitionsAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return capability.SecurityAgentExistingTestDefinitionsAvailable(ctx)
}

func (database *tracedJSONDatabase) SecurityAgentRunContextAvailable(ctx context.Context) (bool, error) {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil || ctx.Err() != nil {
		return false, apiserver.ErrRepositoryUnavailable
	}
	capability, ok := database.next.(interface {
		SecurityAgentRunContextAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return capability.SecurityAgentRunContextAvailable(ctx)
}

func (database *tracedJSONDatabase) VerifySecurityAgentBudgetRelease(ctx context.Context) error {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil || ctx.Err() != nil {
		return apiserver.ErrRepositoryUnavailable
	}
	verifier, ok := database.next.(interface{ VerifySecurityAgentBudgetRelease(context.Context) error })
	if !ok {
		return nil
	}
	return verifier.VerifySecurityAgentBudgetRelease(ctx)
}

func (database *tracedJSONDatabase) SchemaVersion(ctx context.Context) (value string, err error) {
	ctx, end := startOperationalSpan(ctx, database.exporter, "repository.schema", "client", map[string]string{"db.system": "postgresql", "db.operation.name": "schema"})
	defer func() { database.metrics.observeDependency("repository", err); end(err) }()
	return database.next.SchemaVersion(ctx)
}

func (database *tracedJSONDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (value json.RawMessage, err error) {
	ctx, end := startOperationalSpan(ctx, database.exporter, "repository.query", "client", map[string]string{"db.system": "postgresql", "db.operation.name": "query"})
	defer func() { database.metrics.observeDependency("repository", err); end(err) }()
	return database.next.QueryJSON(ctx, statement, arguments...)
}

func (database *tracedJSONDatabase) Exec(ctx context.Context, statement string, arguments ...any) (err error) {
	ctx, end := startOperationalSpan(ctx, database.exporter, "repository.exec", "client", map[string]string{"db.system": "postgresql", "db.operation.name": "exec"})
	defer func() { database.metrics.observeDependency("repository", err); end(err) }()
	return database.next.Exec(ctx, statement, arguments...)
}

type tracedCallbackProvider struct {
	next     apiserver.CallbackProvider
	metrics  *operationalMetrics
	exporter operationalSpanExporter
}

func (provider *tracedCallbackProvider) Complete(ctx context.Context, code, state string) (grant apiserver.SessionGrant, err error) {
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.complete", "client", map[string]string{"server.address": "stytch", "rpc.method": "complete"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return provider.next.Complete(ctx, code, state)
}

func (provider *tracedCallbackProvider) Ready(ctx context.Context) (err error) {
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.ready", "client", map[string]string{"server.address": "stytch", "rpc.method": "ready"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return provider.next.Ready(ctx)
}

func (provider *tracedCallbackProvider) Start(ctx context.Context, returnTo string) (target string, err error) {
	starter, ok := provider.next.(apiserver.IdentityStarter)
	if !ok {
		return "", errRuntimeUnavailable
	}
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.start", "client", map[string]string{"server.address": "stytch", "rpc.method": "start"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return starter.Start(ctx, returnTo)
}

func (provider *tracedCallbackProvider) identityConnections() (apiserver.IdentityConnectionProvider, error) {
	connections, ok := provider.next.(apiserver.IdentityConnectionProvider)
	if !ok {
		return nil, errRuntimeUnavailable
	}
	return connections, nil
}

func (provider *tracedCallbackProvider) ListSSO(ctx context.Context, organization string) (result []platformidentity.SSOConnection, err error) {
	connections, err := provider.identityConnections()
	if err != nil {
		return nil, err
	}
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.sso.list", "client", map[string]string{"server.address": "stytch", "rpc.method": "list_sso"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return connections.ListSSO(ctx, organization)
}

func (provider *tracedCallbackProvider) CreateSSO(ctx context.Context, organization string, config platformidentity.SSOConfig) (result platformidentity.SSOConnection, err error) {
	connections, err := provider.identityConnections()
	if err != nil {
		return result, err
	}
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.sso.create", "client", map[string]string{"server.address": "stytch", "rpc.method": "create_sso"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return connections.CreateSSO(ctx, organization, config)
}

func (provider *tracedCallbackProvider) DeleteSSO(ctx context.Context, organization, reference string) (err error) {
	connections, err := provider.identityConnections()
	if err != nil {
		return err
	}
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.sso.delete", "client", map[string]string{"server.address": "stytch", "rpc.method": "delete_sso"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return connections.DeleteSSO(ctx, organization, reference)
}

func (provider *tracedCallbackProvider) TestSSO(ctx context.Context, organization, reference string) (err error) {
	connections, err := provider.identityConnections()
	if err != nil {
		return err
	}
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.sso.test", "client", map[string]string{"server.address": "stytch", "rpc.method": "test_sso"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return connections.TestSSO(ctx, organization, reference)
}

func (provider *tracedCallbackProvider) ListSCIM(ctx context.Context, organization string) (result []platformidentity.SCIMConnection, err error) {
	connections, err := provider.identityConnections()
	if err != nil {
		return nil, err
	}
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.scim.list", "client", map[string]string{"server.address": "stytch", "rpc.method": "list_scim"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return connections.ListSCIM(ctx, organization)
}

func (provider *tracedCallbackProvider) CreateSCIM(ctx context.Context, organization string, config platformidentity.SCIMConfig) (result platformidentity.SCIMCredential, err error) {
	connections, err := provider.identityConnections()
	if err != nil {
		return result, err
	}
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.scim.create", "client", map[string]string{"server.address": "stytch", "rpc.method": "create_scim"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return connections.CreateSCIM(ctx, organization, config)
}

func (provider *tracedCallbackProvider) DeleteSCIM(ctx context.Context, organization, reference string) (err error) {
	connections, err := provider.identityConnections()
	if err != nil {
		return err
	}
	ctx, end := startOperationalSpan(ctx, provider.exporter, "identity.scim.delete", "client", map[string]string{"server.address": "stytch", "rpc.method": "delete_scim"})
	defer func() { provider.metrics.observeDependency("provider", err); end(err) }()
	return connections.DeleteSCIM(ctx, organization, reference)
}

func generateCorrelationID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return ""
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return "pid_" + encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

type pgxProductionDriver struct{ pool *pgxpool.Pool }

func (driver *pgxProductionDriver) Begin(ctx context.Context) (pgx.Tx, error) {
	if driver == nil || driver.pool == nil {
		return nil, errors.New("database unavailable")
	}
	return driver.pool.Begin(ctx)
}

func (driver *pgxProductionDriver) QueryRow(ctx context.Context, statement string, arguments ...any) apiserver.PostgresRow {
	if driver == nil || driver.pool == nil {
		return unavailablePostgresRow{}
	}
	return driver.pool.QueryRow(ctx, statement, arguments...)
}
func (driver *pgxProductionDriver) Exec(ctx context.Context, statement string, arguments ...any) error {
	if driver == nil || driver.pool == nil {
		return errors.New("database unavailable")
	}
	_, err := driver.pool.Exec(ctx, statement, arguments...)
	return err
}
func (driver *pgxProductionDriver) Close() error {
	if driver != nil && driver.pool != nil {
		driver.pool.Close()
	}
	return nil
}

type unavailablePostgresRow struct{}

func (unavailablePostgresRow) Scan(...any) error { return errors.New("database unavailable") }
