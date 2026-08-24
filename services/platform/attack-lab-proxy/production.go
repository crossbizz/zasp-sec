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

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklabproxy"
	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

const (
	proxyListenAddress  = ":8443"
	healthListenAddress = ":8081"
)

type proxyPostgresDatabase struct{ connection *pgx.Conn }

func (database proxyPostgresDatabase) SchemaVersion(context.Context) (string, error) {
	return "", errRuntimeUnavailable
}

func (database proxyPostgresDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	if database.connection == nil {
		return nil, errRuntimeUnavailable
	}
	var value json.RawMessage
	if err := database.connection.QueryRow(ctx, statement, arguments...).Scan(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func (database proxyPostgresDatabase) Exec(ctx context.Context, statement string, arguments ...any) error {
	if database.connection == nil {
		return errRuntimeUnavailable
	}
	_, err := database.connection.Exec(ctx, statement, arguments...)
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
	connection, err := pgx.Connect(ctx, config.DatabaseURL)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	var cloud *redteamadapter.CloudAuthority
	fail := func() (*productionDependencies, error) {
		if cloud != nil {
			cloud.Close()
		}
		_ = connection.Close(context.Background())
		return nil, errRuntimeUnavailable
	}
	repository, err := apiserver.NewAttackLabExecutionRepository(proxyPostgresDatabase{connection: connection}, apiserver.AttackLabExecutionAuthorityProxy)
	if err != nil {
		return fail()
	}
	key, ok := readProxyPinnedFile(config.SigningKeyFile, 32, 64)
	if !ok {
		return fail()
	}
	defer clear(key)
	cloud, err = redteamadapter.NewProductionCloudAuthority(config.AWS)
	if err != nil || cloud.Ready(ctx) != nil {
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
		if readyCtx == nil || readyCtx.Err() != nil || repository.Ready(readyCtx) != nil || cloud.Ready(readyCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	var closeOnce sync.Once
	var closeErr error
	closeDependencies := func() error {
		closeOnce.Do(func() {
			handler.Close()
			cloud.Close()
			bounded, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
			defer cancel()
			closeErr = connection.Close(bounded)
		})
		return closeErr
	}
	return &productionDependencies{handler: handler, ready: ready, close: closeDependencies}, nil
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
	proxyServer := &http.Server{Handler: dependencies.handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: config.RequestTimeout, WriteTimeout: config.RequestTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	health, err := healthserver.New(healthserver.Config{Service: "attack-lab-proxy", Version: version, ReadyCheck: func(probeCtx context.Context) bool { return dependencies.ready(probeCtx) == nil }, ReadyInterval: 5 * time.Second, ReadyMaxInterval: 30 * time.Second})
	if err != nil {
		_ = tlsListener.Close()
		_ = healthListener.Close()
		return errRuntimeUnavailable
	}
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
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
