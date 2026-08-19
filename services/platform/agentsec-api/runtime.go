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
	Environment           string
	DeploymentMode        string
	OrganizationID        string
	ProductListenAddress  string
	InternalListenAddress string
	PublicOrigin          string
	TrustedProxyCIDRs     []string
	RequestRatePerSecond  int
	RequestBurst          int
	CookieSecure          bool
	ProviderTimeout       time.Duration
	RequestTimeout        time.Duration
	ShutdownTimeout       time.Duration
	ReadinessInterval     time.Duration
	ReadinessMaxInterval  time.Duration
	PostgresDSN           string
	StytchBaseURL         string
	StytchAuthorizeURL    string
	StytchProjectID       string
	StytchSecret          string
	StytchPublicToken     string
	StytchOrganizationID  string
	WorkflowSigningKey    string
	TokenRevealKey        []byte
}

type StoreDependency struct {
	Name    string
	Durable bool
}

type RuntimeDependencies struct {
	ProductHandler http.Handler
	ReadinessCheck func(context.Context) error
	Stores         []StoreDependency
	Closers        []io.Closer
	Metrics        *operationalMetrics
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
		PostgresDSN: getenv("ZASP_POSTGRES_DSN"), StytchBaseURL: getenv("ZASP_STYTCH_BASE_URL"), StytchAuthorizeURL: getenv("ZASP_STYTCH_AUTHORIZE_URL"), StytchProjectID: getenv("ZASP_STYTCH_PROJECT_ID"), StytchSecret: getenv("ZASP_STYTCH_SECRET"), StytchPublicToken: getenv("ZASP_STYTCH_PUBLIC_TOKEN"), StytchOrganizationID: getenv("ZASP_STYTCH_ORGANIZATION_ID"), WorkflowSigningKey: getenv("ZASP_WORKFLOW_SIGNING_KEY"),
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
	for _, value := range config.TrustedProxyCIDRs {
		_, network, parseErr := net.ParseCIDR(value)
		if parseErr != nil || network.String() != value {
			return false
		}
	}
	database, databaseErr := url.Parse(config.PostgresDSN)
	if databaseErr != nil || database.Scheme != "postgres" && database.Scheme != "postgresql" || database.Host == "" || database.User == nil || database.Path == "" || strings.TrimSpace(config.PostgresDSN) != config.PostgresDSN {
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
	return config.ProviderTimeout > 0 && config.ProviderTimeout <= 30*time.Second && config.RequestTimeout > 0 && config.RequestTimeout <= 30*time.Second && config.ShutdownTimeout > 0 && config.ShutdownTimeout <= 30*time.Second && config.ReadinessInterval >= 100*time.Millisecond && config.ReadinessMaxInterval >= config.ReadinessInterval && config.ReadinessMaxInterval <= 5*time.Minute
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
	go func() { productDone <- productServer.Serve(productListener) }()
	go func() { internalDone <- health.Serve(runtimeCtx, internalListener) }()

	var productErr, internalErr error
	select {
	case <-ctx.Done():
	case productErr = <-productDone:
		cancel()
	case internalErr = <-internalDone:
		cancel()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	shutdownErr := productServer.Shutdown(shutdownCtx)
	shutdownCancel()
	cancel()
	if productErr == nil {
		productErr = <-productDone
	}
	if internalErr == nil {
		internalErr = <-internalDone
	}
	if ctx.Err() != nil && (productErr == nil || errors.Is(productErr, http.ErrServerClosed)) && internalErr == nil && shutdownErr == nil {
		return nil
	}
	return errors.Join(errRuntimeUnavailable, productErr, internalErr, shutdownErr)
}

func writeLifecycle(output io.Writer, event, version string) error {
	if output == nil || event != "runtime_started" && event != "runtime_stopped" || !validBuildVersion(version) {
		return errRuntimeUnavailable
	}
	return json.NewEncoder(output).Encode(map[string]string{"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "severity": "INFO", "event": event, "service": "agentsec-api", "version": version})
}
