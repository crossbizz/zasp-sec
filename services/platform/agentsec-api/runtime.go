package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
)

var (
	errInvalidRuntimeConfig       = errors.New("invalid API runtime configuration")
	errInvalidRuntimeDependencies = errors.New("invalid API runtime dependencies")
)

type RuntimeConfig struct {
	Environment            string
	ProductListenAddress   string
	InternalListenAddress  string
	PublicOrigin           string
	CookieSecure           bool
	ProviderTimeout        time.Duration
	ShutdownTimeout        time.Duration
	PostgresDSN            string
	IdentityCallbackURL    string
	IdentityCallbackBearer string
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
}

func loadRuntimeConfig(getenv func(string) string) (RuntimeConfig, error) {
	if getenv == nil {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	providerTimeout, providerErr := time.ParseDuration(getenv("ZASP_PROVIDER_TIMEOUT"))
	shutdownTimeout, shutdownErr := time.ParseDuration(getenv("ZASP_SHUTDOWN_TIMEOUT"))
	cookieSecure, cookieErr := strconv.ParseBool(getenv("ZASP_COOKIE_SECURE"))
	config := RuntimeConfig{
		Environment: getenv("ZASP_ENVIRONMENT"), ProductListenAddress: getenv("ZASP_PRODUCT_LISTEN_ADDRESS"),
		InternalListenAddress: getenv("ZASP_INTERNAL_LISTEN_ADDRESS"), PublicOrigin: getenv("ZASP_PUBLIC_ORIGIN"),
		CookieSecure: cookieSecure, ProviderTimeout: providerTimeout, ShutdownTimeout: shutdownTimeout,
		PostgresDSN: getenv("ZASP_POSTGRES_DSN"), IdentityCallbackURL: getenv("ZASP_IDENTITY_CALLBACK_URL"), IdentityCallbackBearer: getenv("ZASP_IDENTITY_CALLBACK_BEARER"),
	}
	if providerErr != nil || shutdownErr != nil || cookieErr != nil || !validRuntimeConfig(config) {
		return RuntimeConfig{}, errInvalidRuntimeConfig
	}
	return config, nil
}

func validRuntimeConfig(config RuntimeConfig) bool {
	if config.Environment != "production" && config.Environment != "development" && config.Environment != "test" {
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
	database, databaseErr := url.Parse(config.PostgresDSN)
	if databaseErr != nil || database.Scheme != "postgres" && database.Scheme != "postgresql" || database.Host == "" || database.User == nil || database.Path == "" || strings.TrimSpace(config.PostgresDSN) != config.PostgresDSN {
		return false
	}
	callback, callbackErr := url.Parse(config.IdentityCallbackURL)
	if callbackErr != nil || callback.Scheme != "https" || callback.Host == "" || callback.User != nil || callback.RawQuery != "" || callback.Fragment != "" || callback.Path != "" || len(config.IdentityCallbackBearer) < 8 || len(config.IdentityCallbackBearer) > 4096 || strings.TrimSpace(config.IdentityCallbackBearer) != config.IdentityCallbackBearer {
		return false
	}
	return config.ProviderTimeout > 0 && config.ProviderTimeout <= 30*time.Second && config.ShutdownTimeout > 0 && config.ShutdownTimeout <= 30*time.Second
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
	health, err := healthserver.New(healthserver.Config{Service: "agentsec-api", Version: version, ReadyCheck: func(checkCtx context.Context) bool {
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
