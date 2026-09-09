package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklabproxy"
	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

const (
	proxyListenAddress  = ":8443"
	healthListenAddress = ":8081"
)

type proxyPostgresDatabase struct {
	connection *pgxpool.Pool
	lifetime   context.Context
	timeout    time.Duration
}

func connectProxyDatabase(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	config.MaxConns, config.MinConns = 8, 1
	connection, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	if err := connection.Ping(ctx); err != nil {
		connection.Close()
		return nil, errRuntimeUnavailable
	}
	return connection, nil
}

func (database proxyPostgresDatabase) queryContext(ctx context.Context) (context.Context, func(), error) {
	if database.connection == nil || ctx == nil || ctx.Err() != nil || database.lifetime != nil && database.lifetime.Err() != nil {
		return nil, nil, errRuntimeUnavailable
	}
	bounded, cancel := context.WithCancel(ctx)
	var cancelTimeout context.CancelFunc = func() {}
	if database.timeout > 0 {
		bounded, cancelTimeout = context.WithTimeout(bounded, database.timeout)
	}
	var stop func() bool = func() bool { return true }
	if database.lifetime != nil {
		stop = context.AfterFunc(database.lifetime, cancel)
	}
	return bounded, func() { stop(); cancelTimeout(); cancel() }, nil
}

func (database proxyPostgresDatabase) SchemaVersion(context.Context) (string, error) {
	return "", errRuntimeUnavailable
}

func (database proxyPostgresDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	bounded, cancel, err := database.queryContext(ctx)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	defer cancel()
	var value json.RawMessage
	if err := database.connection.QueryRow(bounded, statement, arguments...).Scan(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func (database proxyPostgresDatabase) Exec(ctx context.Context, statement string, arguments ...any) error {
	bounded, cancel, err := database.queryContext(ctx)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer cancel()
	_, err = database.connection.Exec(bounded, statement, arguments...)
	return err
}

type productionDependencies struct {
	handler http.Handler
	ready   func(context.Context) error
	close   func() error
}

func buildProductionDependencies(ctx context.Context, config runtimeConfig) (*productionDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validRuntimeConfig(config) {
		return nil, errRuntimeUnavailable
	}
	lifetime, cancelLifetime := context.WithCancel(ctx)
	startup, cancelStartup := context.WithTimeout(lifetime, config.RequestTimeout)
	defer cancelStartup()
	connection, err := connectProxyDatabase(startup, config.DatabaseURL)
	if err != nil {
		cancelLifetime()
		return nil, errRuntimeUnavailable
	}
	var cloud *redteamadapter.CloudAuthority
	fail := func() (*productionDependencies, error) {
		cancelLifetime()
		if cloud != nil {
			cloud.Close()
		}
		connection.Close()
		return nil, errRuntimeUnavailable
	}
	repository, err := apiserver.NewAttackLabExecutionRepository(proxyPostgresDatabase{connection: connection, lifetime: lifetime, timeout: config.RequestTimeout}, apiserver.AttackLabExecutionAuthorityProxy)
	if err != nil || repository.Ready(startup) != nil {
		return fail()
	}
	key, ok := readProxyPinnedFile(config.SigningKeyFile, 32, 64)
	if !ok {
		return fail()
	}
	defer clear(key)
	cloud, err = redteamadapter.NewProductionCloudAuthority(config.AWS)
	if err != nil || cloud.Ready(startup) != nil {
		return fail()
	}
	authorizer, err := attacklabproxy.NewTargetAuthorizer(cloud.CredentialResolver())
	if err != nil {
		return fail()
	}
	forwarder, err := attacklabproxy.NewHTTPSForwarder(config.AllowedTargetCIDRs, config.RequestTimeout, config.MaximumResponseBytes, authorizer)
	if err != nil {
		return fail()
	}
	handler, err := attacklabproxy.NewHandler(attacklabproxy.Config{SigningKey: key, MaximumRequestBytes: config.MaximumRequestBytes, MaximumResponseBytes: config.MaximumResponseBytes, Clock: func() time.Time { return time.Now().UTC() }}, repository, forwarder)
	if err != nil {
		return fail()
	}
	ready := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil {
			return errRuntimeUnavailable
		}
		readyCtx, cancel := context.WithTimeout(readyCtx, config.RequestTimeout)
		defer cancel()
		stop := context.AfterFunc(lifetime, cancel)
		defer stop()
		if repository.Ready(readyCtx) != nil || cloud.Ready(readyCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	var closeOnce sync.Once
	var closeErr error
	closeDependencies := func() error {
		closeOnce.Do(func() {
			cancelLifetime()
			handler.Close()
			cloud.Close()
			closed := make(chan struct{})
			go func() { connection.Close(); close(closed) }()
			timer := time.NewTimer(config.ShutdownTimeout)
			defer timer.Stop()
			select {
			case <-closed:
			case <-timer.C:
				closeErr = errRuntimeUnavailable
			}
		})
		return closeErr
	}
	return &productionDependencies{handler: handler, ready: ready, close: closeDependencies}, nil
}

func newProxyHTTPServer(ctx context.Context, config runtimeConfig, handler http.Handler) *http.Server {
	bounded := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCtx, cancel := context.WithTimeout(request.Context(), config.RequestTimeout)
		defer cancel()
		handler.ServeHTTP(writer, request.WithContext(requestCtx))
	})
	return &http.Server{Handler: bounded, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: config.RequestTimeout, WriteTimeout: config.RequestTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
}

func serveProduction(ctx context.Context, version string, config runtimeConfig, dependencies *productionDependencies, listen func(string, string) (net.Listener, error)) error {
	if ctx == nil || ctx.Err() != nil || version == "" || len(version) > 64 || !validRuntimeConfig(config) || dependencies == nil || dependencies.handler == nil || dependencies.ready == nil || dependencies.close == nil || listen == nil {
		return errRuntimeUnavailable
	}
	defer dependencies.close()
	certificate, err := loadPinnedTLSCertificate(config.TLSCertificateFile, config.TLSPrivateKeyFile)
	if err != nil {
		return errRuntimeUnavailable
	}
	proxyListener, err := listen("tcp", proxyListenAddress)
	if err != nil {
		return errRuntimeUnavailable
	}
	healthListener, err := listen("tcp", healthListenAddress)
	if err != nil {
		_ = proxyListener.Close()
		return errRuntimeUnavailable
	}
	tlsListener := tls.NewListener(proxyListener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	proxyServer := newProxyHTTPServer(serveCtx, config, dependencies.handler)
	health, err := healthserver.New(healthserver.Config{Service: "attack-lab-proxy", Version: version, ReadyCheck: func(probeCtx context.Context) bool { return dependencies.ready(probeCtx) == nil }, ReadyInterval: 5 * time.Second, ReadyMaxInterval: 30 * time.Second})
	if err != nil {
		_ = tlsListener.Close()
		_ = healthListener.Close()
		return errRuntimeUnavailable
	}
	serveErrors := make(chan error, 2)
	go func() { serveErrors <- proxyServer.Serve(tlsListener) }()
	go func() { serveErrors <- health.Serve(serveCtx, healthListener) }()
	var result error
	select {
	case <-ctx.Done():
	case result = <-serveErrors:
	}
	stopServing()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	defer cancel()
	shutdownErr := proxyServer.Shutdown(shutdownCtx)
	closeErr := dependencies.close()
	if result != nil && !errors.Is(result, http.ErrServerClosed) || shutdownErr != nil || closeErr != nil {
		return errRuntimeUnavailable
	}
	return nil
}

var _ apiserver.JSONDatabase = proxyPostgresDatabase{}
