package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
)

var (
	errInvalidRuntimeConfig       = errors.New("invalid API runtime configuration")
	errInvalidRuntimeDependencies = errors.New("invalid API runtime dependencies")
)

type RuntimeConfig struct {
	Environment                 string
	DeploymentMode              string
	OrganizationID              string
	ProductListenAddress        string
	InternalListenAddress       string
	PublicOrigin                string
	TrustedProxyCIDRs           []string
	RequestRatePerSecond        int
	RequestBurst                int
	CookieSecure                bool
	ProviderTimeout             time.Duration
	RequestTimeout              time.Duration
	ShutdownTimeout             time.Duration
	ReadinessInterval           time.Duration
	ReadinessMaxInterval        time.Duration
	DiscoveryParserVersion      string
	DiscoveryToolVersion        string
	PostgresDSN                 string
	SecurityAgentPostgresDSN    string
	StytchBaseURL               string
	StytchAuthorizeURL          string
	StytchProjectID             string
	StytchSecret                string
	StytchPublicToken           string
	StytchOrganizationID        string
	WorkflowSigningKey          string
	TokenRevealKey              []byte
	ConnectorAWSRegion          string
	ConnectorRoleARN            string
	ConnectorTokenFile          string
	ConnectorKMSKeyARN          string
	ConnectorSecretPrefix       string
	AWSCustomerRolePrefixes     []string
	AWSCustomerRoleARNs         []string
	KubernetesEgressCIDRs       []string
	FindingTicketEgressCIDRs    []string
	GitHubClientID              string
	GitHubSecretReference       string
	GitHubAppID                 string
	GitHubPrivateKeyReference   string
	OktaClientID                string
	OktaSecretReference         string
	NangoBaseURL                string
	NangoServiceSecretReference string
	NangoEnvironment            string
}

type StoreDependency struct {
	Name    string
	Durable bool
}

type RuntimeDependencies struct {
	ProductHandler  http.Handler
	ReadinessCheck  func(context.Context) error
	LifecycleWorker func(context.Context) error
	Stores          []StoreDependency
	Closers         []io.Closer
	Metrics         *operationalMetrics
}

func loadRuntimeConfig(getenv func(string) string) (RuntimeConfig, error) {
	if getenv == nil {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	providerTimeout, providerErr := time.ParseDuration(getenv("ZASP_PROVIDER_TIMEOUT"))
	requestTimeout, requestErr := time.ParseDuration(getenv("ZASP_REQUEST_TIMEOUT"))
	shutdownTimeout, shutdownErr := time.ParseDuration(getenv("ZASP_SHUTDOWN_TIMEOUT"))
	readinessInterval, readinessErr := time.ParseDuration(getenv("ZASP_READINESS_INTERVAL"))
	readinessMaxInterval, readinessMaxErr := time.ParseDuration(getenv("ZASP_READINESS_MAX_INTERVAL"))
	cookieSecure, cookieErr := strconv.ParseBool(getenv("ZASP_COOKIE_SECURE"))
	requestRate, requestRateErr := strconv.Atoi(getenv("ZASP_REQUEST_RATE_PER_SECOND"))
	requestBurst, requestBurstErr := strconv.Atoi(getenv("ZASP_REQUEST_BURST"))
	config := RuntimeConfig{
		Environment: getenv("ZASP_ENVIRONMENT"), DeploymentMode: getenv("ZASP_DEPLOYMENT_MODE"), OrganizationID: getenv("ZASP_ORGANIZATION_ID"), ProductListenAddress: getenv("ZASP_PRODUCT_LISTEN_ADDRESS"),
		InternalListenAddress: getenv("ZASP_INTERNAL_LISTEN_ADDRESS"), PublicOrigin: getenv("ZASP_PUBLIC_ORIGIN"),
		TrustedProxyCIDRs: parseTrustedProxyCIDRs(getenv("ZASP_TRUSTED_PROXY_CIDRS")), RequestRatePerSecond: requestRate, RequestBurst: requestBurst,
		CookieSecure: cookieSecure, ProviderTimeout: providerTimeout, RequestTimeout: requestTimeout, ShutdownTimeout: shutdownTimeout,
		ReadinessInterval: readinessInterval, ReadinessMaxInterval: readinessMaxInterval,
		DiscoveryParserVersion: getenv("ZASP_DISCOVERY_PARSER_VERSION"), DiscoveryToolVersion: getenv("ZASP_DISCOVERY_TOOL_VERSION"),
		PostgresDSN: getenv("ZASP_POSTGRES_DSN"), SecurityAgentPostgresDSN: getenv("ZASP_SECURITY_AGENT_POSTGRES_DSN"), StytchBaseURL: getenv("ZASP_STYTCH_BASE_URL"), StytchAuthorizeURL: getenv("ZASP_STYTCH_AUTHORIZE_URL"), StytchProjectID: getenv("ZASP_STYTCH_PROJECT_ID"), StytchSecret: getenv("ZASP_STYTCH_SECRET"), StytchPublicToken: getenv("ZASP_STYTCH_PUBLIC_TOKEN"), StytchOrganizationID: getenv("ZASP_STYTCH_ORGANIZATION_ID"), WorkflowSigningKey: getenv("ZASP_WORKFLOW_SIGNING_KEY"),
		ConnectorAWSRegion: getenv("ZASP_CONNECTOR_AWS_REGION"), ConnectorRoleARN: getenv("ZASP_CONNECTOR_ROLE_ARN"), ConnectorTokenFile: getenv("ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE"), ConnectorKMSKeyARN: getenv("ZASP_CONNECTOR_KMS_KEY_ARN"), ConnectorSecretPrefix: getenv("ZASP_CONNECTOR_SECRET_PREFIX"),
		AWSCustomerRolePrefixes: parseAWSCustomerRolePrefixes(getenv("ZASP_AWS_CUSTOMER_ROLE_PREFIXES")), AWSCustomerRoleARNs: parseAWSCustomerRoleARNs(getenv("ZASP_AWS_CUSTOMER_ROLE_ARNS")), KubernetesEgressCIDRs: parseTrustedProxyCIDRs(getenv("ZASP_KUBERNETES_EGRESS_CIDRS")), FindingTicketEgressCIDRs: parseTrustedProxyCIDRs(getenv("ZASP_FINDING_TICKET_EGRESS_CIDRS")),
		GitHubClientID: getenv("ZASP_GITHUB_CLIENT_ID"), GitHubSecretReference: getenv("ZASP_GITHUB_CLIENT_SECRET_REFERENCE"), GitHubAppID: getenv("ZASP_GITHUB_APP_ID"), GitHubPrivateKeyReference: getenv("ZASP_GITHUB_PRIVATE_KEY_REFERENCE"), OktaClientID: getenv("ZASP_OKTA_CLIENT_ID"), OktaSecretReference: getenv("ZASP_OKTA_CLIENT_SECRET_REFERENCE"),
		NangoBaseURL: getenv("ZASP_NANGO_BASE_URL"), NangoServiceSecretReference: getenv("ZASP_NANGO_SERVICE_SECRET_REFERENCE"), NangoEnvironment: getenv("ZASP_NANGO_ENVIRONMENT"),
	}
	revealKey := getenv("ZASP_TOKEN_REVEAL_KEY")
	decodedRevealKey, revealKeyErr := base64.RawURLEncoding.DecodeString(revealKey)
	if revealKeyErr == nil && base64.RawURLEncoding.EncodeToString(decodedRevealKey) == revealKey {
		config.TokenRevealKey = append([]byte(nil), decodedRevealKey...)
	}
	if providerErr != nil || requestErr != nil || shutdownErr != nil || readinessErr != nil || readinessMaxErr != nil || cookieErr != nil || requestRateErr != nil || requestBurstErr != nil || revealKeyErr != nil || !validRuntimeConfig(config) {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	return config, nil
}

func validRuntimeConfig(config RuntimeConfig) bool {
	if config.Environment != "production" && config.Environment != "development" && config.Environment != "test" {
		return false
	}
	if config.DeploymentMode == "saas" && config.OrganizationID != "" {
		return false
	}
	if config.DeploymentMode == "single_tenant" {
		if _, err := domain.ParseProductID(config.OrganizationID); err != nil {
			return false
		}
	} else if config.DeploymentMode != "saas" {
		return false
	}
	if !validListenAddress(config.ProductListenAddress) || !validListenAddress(config.InternalListenAddress) || config.ProductListenAddress == config.InternalListenAddress {
		return false
	}
	origin, err := url.Parse(config.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	if config.Environment == "production" && !config.CookieSecure {
		return false
	}
	if len(config.TrustedProxyCIDRs) == 0 || config.RequestRatePerSecond < 1 || config.RequestRatePerSecond > 10000 || config.RequestBurst < 1 || config.RequestBurst > 10000 {
		return false
	}
	if !connectorRegionPattern.MatchString(config.ConnectorAWSRegion) || !connectorRolePattern.MatchString(config.ConnectorRoleARN) || config.ConnectorTokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || !connectorKMSPattern.MatchString(config.ConnectorKMSKeyARN) || !connectorPrefixPattern.MatchString(config.ConnectorSecretPrefix) || !strings.HasSuffix(config.ConnectorSecretPrefix, "/oauth") || !validAWSCustomerRoleAuthority(config.AWSCustomerRolePrefixes, config.AWSCustomerRoleARNs) || !githubClientPattern.MatchString(config.GitHubClientID) || !connectorReferencePattern.MatchString(config.GitHubSecretReference) || !githubAppIDPattern.MatchString(config.GitHubAppID) || !connectorReferencePattern.MatchString(config.GitHubPrivateKeyReference) || !oktaClientPattern.MatchString(config.OktaClientID) || !connectorReferencePattern.MatchString(config.OktaSecretReference) {
		return false
	}
	for _, value := range config.KubernetesEgressCIDRs {
		_, network, parseErr := net.ParseCIDR(value)
		if parseErr != nil || network.String() != value {
			return false
		}
	}
	if !validFindingTicketEgressCIDRs(config.FindingTicketEgressCIDRs) {
		return false
	}
	if !validOptionalNangoConfig(config) {
		return false
	}
	for _, value := range config.TrustedProxyCIDRs {
		_, network, parseErr := net.ParseCIDR(value)
		if parseErr != nil || network.String() != value {
			return false
		}
	}
	if !validRuntimePostgresAuthorities(config.PostgresDSN, config.SecurityAgentPostgresDSN) {
		return false
	}
	authorize, authorizeErr := url.Parse(config.StytchAuthorizeURL)
	base, baseErr := url.Parse(config.StytchBaseURL)
	if authorizeErr != nil || baseErr != nil || authorize == nil || base == nil {
		return false
	}
	if !validConfiguredIdentityURL(authorize, config.Environment) || authorize.Path == "" || !validConfiguredIdentityURL(base, config.Environment) || base.Path != "" || len(config.StytchProjectID) < 8 || len(config.StytchProjectID) > 256 || strings.TrimSpace(config.StytchProjectID) != config.StytchProjectID || len(config.StytchSecret) < 8 || len(config.StytchSecret) > 4096 || strings.TrimSpace(config.StytchSecret) != config.StytchSecret || len(config.StytchPublicToken) < 8 || len(config.StytchPublicToken) > 256 || !strings.HasPrefix(config.StytchOrganizationID, "organization-") || len(config.StytchOrganizationID) > 128 || len(config.WorkflowSigningKey) < 32 || len(config.WorkflowSigningKey) > 4096 || strings.TrimSpace(config.WorkflowSigningKey) != config.WorkflowSigningKey || len(config.TokenRevealKey) != 32 {
		return false
	}
	return executionVersionPattern.MatchString(config.DiscoveryParserVersion) && executionVersionPattern.MatchString(config.DiscoveryToolVersion) &&
		config.ProviderTimeout > 0 && config.ProviderTimeout <= 30*time.Second && config.RequestTimeout > 0 && config.RequestTimeout <= 30*time.Second && config.ShutdownTimeout > 0 && config.ShutdownTimeout <= 30*time.Second && config.ReadinessInterval >= 100*time.Millisecond && config.ReadinessMaxInterval >= config.ReadinessInterval && config.ReadinessMaxInterval <= 5*time.Minute
}

func validRuntimePostgresAuthorities(coreDSN, securityAgentDSN string) bool {
	core, coreOK := parseRuntimePostgresDSN(coreDSN)
	securityAgent, securityAgentOK := parseRuntimePostgresDSN(securityAgentDSN)
	if !coreOK || !securityAgentOK || core.User.Username() == securityAgent.User.Username() {
		return false
	}
	return core.Scheme == securityAgent.Scheme && core.Host == securityAgent.Host && core.Path == securityAgent.Path && core.RawQuery == securityAgent.RawQuery
}

func parseRuntimePostgresDSN(value string) (*url.URL, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" || parsed.Host == "" || parsed.User == nil || parsed.User.Username() == "" || parsed.Path == "" || strings.TrimSpace(value) != value || parsed.Fragment != "" {
		return nil, false
	}
	return parsed, true
}

func validFindingTicketEgressCIDRs(values []string) bool {
	if len(values) < 1 || len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip, network, err := net.ParseCIDR(value)
		if err != nil || network.String() != value || !ip.Equal(network.IP) || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return false
		}
		ones, bits := network.Mask.Size()
		if bits == 32 && ones < 16 || bits == 128 && ones < 32 || bits != 32 && bits != 128 {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

var executionVersionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)

var connectorRegionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$`)
var connectorRolePattern = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
var connectorKMSPattern = regexp.MustCompile(`^arn:aws:kms:[a-z]{2}(?:-gov)?-[a-z]+-[0-9]:[0-9]{12}:key/[0-9a-f-]{36}$`)
var connectorPrefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{2,127}$`)
var connectorReferencePattern = regexp.MustCompile(`^ref:(?:github|okta)/[a-z0-9][a-z0-9_./:-]{3,507}$`)
var githubClientPattern = regexp.MustCompile(`^Iv1\.[A-Za-z0-9]{16}$`)
var githubAppIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
var oktaClientPattern = regexp.MustCompile(`^0oa[A-Za-z0-9]{16}$`)
var nangoReferencePattern = regexp.MustCompile(`^ref:nango/[a-z0-9][a-z0-9_./:-]{7,507}$`)
var nangoEnvironmentPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

func validOptionalNangoConfig(config RuntimeConfig) bool {
	if config.NangoBaseURL == "" && config.NangoServiceSecretReference == "" && config.NangoEnvironment == "" {
		return true
	}
	if !nangoReferencePattern.MatchString(config.NangoServiceSecretReference) || !nangoEnvironmentPattern.MatchString(config.NangoEnvironment) {
		return false
	}
	parsed, err := url.Parse(config.NangoBaseURL)
	return err == nil && parsed.Scheme == "http" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "" && parsed.Port() != "" && strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".svc.cluster.local") && net.ParseIP(parsed.Hostname()) == nil
}

func parseTrustedProxyCIDRs(value string) []string {
	if value == "" || strings.TrimSpace(value) != value {
		return nil
	}
	entries := strings.Split(value, ",")
	if len(entries) > 16 {
		return nil
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry == "" || strings.TrimSpace(entry) != entry {
			return nil
		}
		if _, duplicate := seen[entry]; duplicate {
			return nil
		}
		seen[entry] = struct{}{}
	}
	return entries
}

func validConfiguredIdentityURL(value *url.URL, environment string) bool {
	loopback := net.ParseIP(value.Hostname()) != nil && net.ParseIP(value.Hostname()).IsLoopback()
	return value.Host != "" && value.User == nil && value.RawQuery == "" && value.Fragment == "" && (value.Scheme == "https" || environment == "test" && value.Scheme == "http" && loopback)
}

func validListenAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.ContainsAny(host, "\r\n") {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number > 0 && number <= 65535
}

func validateRuntime(config RuntimeConfig, dependencies RuntimeDependencies) error {
	if !validRuntimeConfig(config) || invalidRuntimeValue(dependencies.ProductHandler) || dependencies.ReadinessCheck == nil || len(dependencies.Stores) == 0 {
		return errInvalidRuntimeDependencies
	}
	seen := make(map[string]struct{}, len(dependencies.Stores))
	for _, store := range dependencies.Stores {
		if store.Name == "" || strings.TrimSpace(store.Name) != store.Name {
			return errInvalidRuntimeDependencies
		}
		if _, duplicate := seen[store.Name]; duplicate {
			return errInvalidRuntimeDependencies
		}
		if config.Environment == "production" && !store.Durable {
			return errInvalidRuntimeDependencies
		}
		seen[store.Name] = struct{}{}
	}
	for _, closer := range dependencies.Closers {
		if invalidRuntimeValue(closer) {
			return errInvalidRuntimeDependencies
		}
	}
	return nil
}

func serveRuntime(ctx context.Context, output io.Writer, version string, config RuntimeConfig, dependencies RuntimeDependencies, listen func(string, string) (net.Listener, error)) (result error) {
	if invalidRuntimeValue(ctx) || invalidRuntimeValue(output) || listen == nil || !validBuildVersion(version) || validateRuntime(config, dependencies) != nil {
		return errRuntimeUnavailable
	}
	productListener, err := listen("tcp", config.ProductListenAddress)
	if err != nil || invalidRuntimeValue(productListener) {
		if !invalidRuntimeValue(productListener) {
			_ = productListener.Close()
		}
		return errors.Join(errRuntimeUnavailable, err)
	}
	internalListener, err := listen("tcp", config.InternalListenAddress)
	if err != nil || invalidRuntimeValue(internalListener) {
		closeErr := productListener.Close()
		if !invalidRuntimeValue(internalListener) {
			closeErr = errors.Join(closeErr, internalListener.Close())
		}
		return errors.Join(errRuntimeUnavailable, err, closeErr)
	}
	defer func() {
		for index := len(dependencies.Closers) - 1; index >= 0; index-- {
			if err := dependencies.Closers[index].Close(); err != nil {
				result = errRuntimeUnavailable
			}
		}
	}()
	if err := run(output, version); err != nil {
		_ = productListener.Close()
		_ = internalListener.Close()
		return err
	}
	if err := writeLifecycle(output, "runtime_started", version); err != nil {
		_ = productListener.Close()
		_ = internalListener.Close()
		return errRuntimeUnavailable
	}
	defer func() {
		if err := writeLifecycle(output, "runtime_stopped", version); err != nil {
			result = errors.Join(errRuntimeUnavailable, result)
		}
	}()
	var metrics func() string
	if dependencies.Metrics != nil {
		metrics = dependencies.Metrics.Prometheus
	}
	health, err := healthserver.New(healthserver.Config{Service: "agentsec-api", Version: version, Metrics: metrics, ReadyInterval: config.ReadinessInterval, ReadyMaxInterval: config.ReadinessMaxInterval, ReadyCheck: func(checkCtx context.Context) bool {
		checkCtx, cancelCheck := context.WithTimeout(checkCtx, config.ProviderTimeout)
		defer cancelCheck()
		return dependencies.ReadinessCheck(checkCtx) == nil
	}})
	if err != nil {
		return errRuntimeUnavailable
	}
	productServer := &http.Server{
		Handler: dependencies.ProductHandler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: config.ProviderTimeout,
		WriteTimeout: config.ProviderTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	productDone := make(chan error, 1)
	internalDone := make(chan error, 1)
	var workerDone chan error
	go func() { productDone <- productServer.Serve(productListener) }()
	go func() { internalDone <- health.Serve(runtimeCtx, internalListener) }()
	if dependencies.LifecycleWorker != nil {
		workerDone = make(chan error, 1)
		go func() { workerDone <- dependencies.LifecycleWorker(runtimeCtx) }()
	}

	var productErr, internalErr, workerErr error
	workerFinished := false
	select {
	case <-ctx.Done():
	case productErr = <-productDone:
		cancel()
	case internalErr = <-internalDone:
		cancel()
	case workerErr = <-workerDone:
		workerFinished = true
		cancel()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	shutdownErr := productServer.Shutdown(shutdownCtx)
	cancel()
	if productErr == nil {
		productErr = <-productDone
	}
	if internalErr == nil {
		internalErr = <-internalDone
	}
	if workerDone != nil && !workerFinished {
		select {
		case workerErr = <-workerDone:
		case <-shutdownCtx.Done():
			workerErr = shutdownCtx.Err()
		}
	}
	shutdownCancel()
	if ctx.Err() != nil && (productErr == nil || errors.Is(productErr, http.ErrServerClosed)) && internalErr == nil && (workerErr == nil || errors.Is(workerErr, context.Canceled)) && shutdownErr == nil {
		return nil
	}
	return errors.Join(errRuntimeUnavailable, productErr, internalErr, workerErr, shutdownErr)
}

func writeLifecycle(output io.Writer, event, version string) error {
	if output == nil || event != "runtime_started" && event != "runtime_stopped" || !validBuildVersion(version) {
		return errRuntimeUnavailable
	}
	return json.NewEncoder(output).Encode(map[string]string{"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "severity": "INFO", "event": event, "service": "agentsec-api", "version": version})
}
