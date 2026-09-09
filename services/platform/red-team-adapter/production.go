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
	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

type postgresJSONDatabase struct {
	connection *pgxpool.Pool
	lifetime   context.Context
	timeout    time.Duration
}

func connectAdapterDatabase(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
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

func (database postgresJSONDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	if database.connection == nil || ctx == nil || ctx.Err() != nil {
		return nil, errRuntimeUnavailable
	}
	if database.timeout > 0 {
		bounded, cancel := context.WithTimeout(ctx, database.timeout)
		defer cancel()
		ctx = bounded
	}
	if database.lifetime != nil {
		bounded, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(database.lifetime, cancel)
		defer stop()
		defer cancel()
		ctx = bounded
	}
	var value json.RawMessage
	if err := database.connection.QueryRow(ctx, statement, arguments...).Scan(&value); err != nil {
		return nil, err
	}
	return value, nil
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
	connection, err := connectAdapterDatabase(startup, config.DatabaseURL)
	if err != nil {
		cancelLifetime()
		return nil, errRuntimeUnavailable
	}
	fail := func(cloud *redteamadapter.CloudAuthority) (*productionDependencies, error) {
		cancelLifetime()
		if cloud != nil {
			cloud.Close()
		}
		connection.Close()
		return nil, errRuntimeUnavailable
	}
	resolver, err := redteamadapter.NewPostgresResolver(postgresJSONDatabase{connection: connection, lifetime: lifetime, timeout: config.RequestTimeout}, migrations.ProductionRedTeamInvocation().Checksum(), migrations.ProductionRedTeamInvocationSemanticFingerprint())
	if err != nil || resolver.Ready(startup) != nil {
		return fail(nil)
	}
	cloud, err := redteamadapter.NewProductionCloudAuthority(config.AWS)
	if err != nil || cloud.Ready(startup) != nil {
		return fail(cloud)
	}
	invoker, err := redteamadapter.NewProductionHTTPSInvoker(config.AllowedTargetCIDRs, config.RequestTimeout, cloud.CredentialResolver())
	if err != nil {
		return fail(cloud)
	}
	token, err := redteamadapter.LoadWorkerToken(config.WorkerTokenFile)
	if err != nil {
		return fail(cloud)
	}
	defer clear(token)
	handler, err := redteamadapter.NewHandler(redteamadapter.Config{WorkerToken: token, MaximumRequestBytes: config.MaximumRequestBytes}, resolver, invoker)
	if err != nil {
		return fail(cloud)
	}
	ready := func(readyCtx context.Context) error {
		readyCtx, cancel := context.WithTimeout(readyCtx, config.RequestTimeout)
		defer cancel()
		stop := context.AfterFunc(lifetime, cancel)
		defer stop()
		if resolver.Ready(readyCtx) != nil || cloud.Ready(readyCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	var closeOnce sync.Once
	var closeErr error
	closeDependencies := func() error {
		closeOnce.Do(func() {
			cancelLifetime()
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

func newTargetHTTPServer(ctx context.Context, config runtimeConfig, handler http.Handler) *http.Server {
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
	targetListener, err := listen("tcp", targetListenAddress)
	if err != nil {
		return errRuntimeUnavailable
	}
	healthListener, err := listen("tcp", healthListenAddress)
	if err != nil {
		_ = targetListener.Close()
		return errRuntimeUnavailable
	}
	tlsListener := tls.NewListener(targetListener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	targetServer := newTargetHTTPServer(serveCtx, config, dependencies.handler)
	health, err := healthserver.New(healthserver.Config{Service: "red-team-adapter", Version: version, ReadyCheck: func(probeCtx context.Context) bool { return dependencies.ready(probeCtx) == nil }, ReadyInterval: 5 * time.Second, ReadyMaxInterval: 30 * time.Second})
	if err != nil {
		_ = tlsListener.Close()
		_ = healthListener.Close()
		return errRuntimeUnavailable
	}
	serveErrors := make(chan error, 2)
	go func() { serveErrors <- targetServer.Serve(tlsListener) }()
	go func() { serveErrors <- health.Serve(serveCtx, healthListener) }()
	var result error
	select {
	case <-ctx.Done():
	case result = <-serveErrors:
	}
	stopServing()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	defer cancel()
	shutdownErr := targetServer.Shutdown(shutdownCtx)
	closeErr := dependencies.close()
	if result != nil && !errors.Is(result, http.ErrServerClosed) || shutdownErr != nil || closeErr != nil {
		return errRuntimeUnavailable
	}
	return nil
}
