package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
)

func buildRuntimeDependencies(ctx context.Context, config RuntimeConfig) (RuntimeDependencies, error) {
	connectCtx, cancel := context.WithTimeout(ctx, config.ProviderTimeout)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(config.PostgresDSN)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	poolConfig.MaxConns = 20
	poolConfig.MinConns = 2
	poolConfig.HealthCheckPeriod = config.ProviderTimeout
	pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	database, err := apiserver.NewPostgresJSONDatabase(&pgxProductionDriver{pool: pool})
	if err != nil {
		pool.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	authenticator, err := apiserver.NewStytchOAuthAuthenticator(config.StytchBaseURL, config.StytchProjectID, config.StytchSecret, config.ProviderTimeout, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	if err != nil {
		_ = database.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewPostgresRepository(database)
	if err != nil {
		_ = database.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	provider, err := apiserver.NewRepositoryIdentityProviderWithStart(authenticator, repository, repository, config.StytchAuthorizeURL, config.StytchPublicToken, config.StytchOrganizationID, config.PublicOrigin+"/auth/callback")
	if err != nil {
		_ = database.Close()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	dependencies, err := composeRuntimeDependencies(config, database, provider)
	if err != nil {
		_ = database.Close()
		return RuntimeDependencies{}, err
	}
	dependencies.Closers = append(dependencies.Closers, database)
	dependencies.Metrics.poolStats = func() poolSaturation {
		stat := pool.Stat()
		return poolSaturation{Acquired: stat.AcquiredConns(), Idle: stat.IdleConns(), Maximum: stat.MaxConns()}
	}
	return dependencies, nil
}

func composeRuntimeDependencies(config RuntimeConfig, database apiserver.JSONDatabase, provider apiserver.CallbackProvider) (RuntimeDependencies, error) {
	metrics := newOperationalMetrics()
	exporter := newStructuredSpanExporter(os.Stdout)
	tracedDatabase := &tracedJSONDatabase{next: database, metrics: metrics, exporter: exporter}
	tracedProvider := &tracedCallbackProvider{next: provider, metrics: metrics, exporter: exporter}
	repository, err := apiserver.NewPostgresRepository(tracedDatabase)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	connectorRepository, err := apiserver.NewConnectorRepository(tracedDatabase)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	secretsClient, secretsTransport, err := newConnectorSecretsClient(config)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	secretsDriver := &connectorSecretsDriver{client: secretsClient}
	secretStore, err := apiserver.NewDurableOAuthSecretStore(secretsDriver, config.ConnectorSecretPrefix, config.ConnectorKMSKeyARN, config.ProviderTimeout, func() time.Time { return time.Now().UTC() })
	if err != nil {
		secretsTransport.CloseIdleConnections()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	providerHTTP, err := newConnectorHTTPClient(config.ProviderTimeout)
	if err != nil {
		secretsTransport.CloseIdleConnections()
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	providerTransport, ok := providerHTTP.Transport.(*http.Transport)
	if !ok {
		secretsTransport.CloseIdleConnections()
		providerHTTP.CloseIdleConnections()
		return RuntimeDependencies{}, errRuntimeUnavailable
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
	providerSecrets := &connectorProviderSecrets{driver: secretsDriver, root: strings.TrimSuffix(config.ConnectorSecretPrefix, "/oauth"), kmsKey: config.ConnectorKMSKeyARN}
	githubAdapter, err := githubdiscovery.NewAdapter(githubdiscovery.Config{ClientID: config.GitHubClientID, ClientSecretReference: config.GitHubSecretReference, CallbackURL: config.PublicOrigin + "/api/v1/integrations/oauth/callback"}, &githubExchangeClient{http: providerHTTP, secrets: providerSecrets, appID: config.GitHubAppID, privateKeyReference: config.GitHubPrivateKeyReference}, config.ProviderTimeout)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	connectorRegistry, err := apiserver.NewConnectorProviderRegistry(map[string]apiserver.ConnectorOAuthProviderDefinition{
		"github": {Provider: &githubOAuthProvider{adapter: githubAdapter}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"},
		"okta":   {Factory: &oktaOAuthFactory{clientID: config.OktaClientID, secretReference: config.OktaSecretReference, callback: config.PublicOrigin + "/api/v1/integrations/oauth/callback", exchange: &oktaExchangeClient{http: providerHTTP, secrets: providerSecrets}, timeout: config.ProviderTimeout}, RequestedScopes: []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}, CredentialClass: "okta_refresh_reference"},
	}, map[string]apiserver.ConnectorCapabilityCheck{
		"github": func(ctx context.Context) error {
			return errors.Join(providerSecrets.ready(ctx, config.GitHubSecretReference), providerSecrets.ready(ctx, config.GitHubPrivateKeyReference))
		},
		"okta": func(ctx context.Context) error { return providerSecrets.ready(ctx, config.OktaSecretReference) },
	})
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	connectorHandler, err := apiserver.NewConnectorHTTPHandler(apiserver.ConnectorHTTPConfig{
		Repository: connectorRepository, Workflows: repository, Secrets: secretStore, Clock: func() time.Time { return time.Now().UTC() }, Registry: connectorRegistry,
	})
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	workerOwner, err := newConnectorWorkerOwner(os.Getenv("HOSTNAME"), rand.Reader)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	connectorReconciler, err := apiserver.NewConnectorReconciler(apiserver.ConnectorReconcilerConfig{Repository: connectorRepository, Workflows: repository, Registry: connectorRegistry, Secrets: secretStore, Owner: workerOwner, LeaseSeconds: 30, Limit: 25, Interval: time.Second})
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	handlers, authenticate, err := apiserver.NewProductionHandlers(repository, tracedProvider, connectorHandler, apiserver.CookiePolicy{Secure: config.CookieSecure, WorkflowSigningKey: []byte(config.WorkflowSigningKey), TokenRevealKey: config.TokenRevealKey, Clock: func() time.Time { return time.Now().UTC().Truncate(time.Second) }, BuildVersion: buildVersion, DeploymentMode: config.DeploymentMode, OrganizationID: config.OrganizationID, ConnectorCapabilities: connectorRegistry})
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	composition, err := apiserver.NewComposition(handlers)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	product, err := apiserver.NewProductMiddleware(apiserver.ProductSecurity{
		PublicOrigin: config.PublicOrigin, MaximumBodyBytes: 16 * 1024, Authenticate: authenticate, GenerateCorrelationID: generateCorrelationID,
	}, composition)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	operational, err := newOperationalMiddleware(os.Stdout, metrics, newRequestLimiter(config.RequestRatePerSecond, config.RequestBurst, 10000, time.Now), config.RequestTimeout, exporter, product)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	edge, err := newEdgeSecurityMiddleware(edgeSecurityConfig{PublicOrigin: config.PublicOrigin, TrustedProxyCIDRs: config.TrustedProxyCIDRs}, operational)
	if err != nil {
		return RuntimeDependencies{}, errRuntimeUnavailable
	}
	keepConnectorResources = true
	return RuntimeDependencies{ProductHandler: edge, Metrics: metrics, LifecycleWorker: connectorReconciler.Run, ReadinessCheck: func(ctx context.Context) error {
		if err := repository.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if err := connectorRepository.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if err := tracedProvider.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if !connectorReconciler.Ready() {
			return errRuntimeUnavailable
		}
		return nil
	}, Stores: []StoreDependency{{Name: "postgres-core", Durable: true}, {Name: "aws-secrets-manager-oauth", Durable: true}}, Closers: connectorResources}, nil
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
	next     apiserver.JSONDatabase
	metrics  *operationalMetrics
	exporter operationalSpanExporter
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
