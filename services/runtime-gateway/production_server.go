package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
)

const productionGatewayListenAddress = ":8080"

func serveProductionGateway(ctx context.Context, output io.Writer, version string, config productionGatewayConfig, dependencies productionGatewayDependencies, listen func(string, string) (net.Listener, error)) (resultErr error) {
	if invalidRuntimeValue(ctx) || invalidRuntimeValue(output) || !validBuildVersion(version) || !validProductionGatewayConfig(config) || invalidRuntimeValue(dependencies.Handler) || dependencies.Ready == nil || dependencies.Metrics == nil || dependencies.Run == nil || dependencies.Drain == nil || dependencies.Close == nil || listen == nil {
		return errRuntimeUnavailable
	}
	defer func() {
		if recover() != nil {
			resultErr = errRuntimeUnavailable
		}
		if closeErr := dependencies.Close(); closeErr != nil && resultErr == nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	if ctx.Err() != nil {
		return nil
	}
	privateListener, err := listen("tcp", productionGatewayListenAddress)
	if err != nil || invalidRuntimeValue(privateListener) {
		if !invalidRuntimeValue(privateListener) {
			_ = privateListener.Close()
		}
		return errRuntimeUnavailable
	}
	healthListener, err := listen("tcp", healthListenAddress)
	if err != nil || invalidRuntimeValue(healthListener) {
		_ = privateListener.Close()
		if !invalidRuntimeValue(healthListener) {
			_ = healthListener.Close()
		}
		return errRuntimeUnavailable
	}
	if err := run(output, version); err != nil {
		_ = privateListener.Close()
		_ = healthListener.Close()
		return err
	}
	health, err := healthserver.New(healthserver.Config{
		Service: "runtime-gateway", Version: version, ReadyInterval: time.Second, ReadyMaxInterval: 30 * time.Second,
		ReadyCheck: func(readyCtx context.Context) bool { return dependencies.Ready(readyCtx) == nil },
		Metrics:    dependencies.Metrics,
	})
	if err != nil {
		_ = privateListener.Close()
		_ = healthListener.Close()
		return errRuntimeUnavailable
	}
	private := &http.Server{Handler: dependencies.Handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: config.OperationTimeout, WriteTimeout: config.OperationTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type serveResult struct {
		name string
		err  error
	}
	results := make(chan serveResult, 3)
	go func() { results <- serveResult{name: "private", err: private.Serve(privateListener)} }()
	go func() { results <- serveResult{name: "health", err: health.Serve(runtimeCtx, healthListener)} }()
	go func() { results <- serveResult{name: "background", err: dependencies.Run(runtimeCtx)} }()

	first := serveResult{}
	select {
	case <-ctx.Done():
	case first = <-results:
		cancel()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	shutdownErr := private.Shutdown(shutdownCtx)
	drainErr := dependencies.Drain(shutdownCtx)
	shutdownCancel()
	closeErr := private.Close()
	_ = privateListener.Close()
	_ = healthListener.Close()

	seen := 0
	if first.name != "" {
		seen = 1
	}
	deadline := time.NewTimer(config.ShutdownTimeout)
	defer deadline.Stop()
	for seen < 3 {
		select {
		case value := <-results:
			seen++
			if first.name == "" {
				first = value
			}
		case <-deadline.C:
			return errRuntimeUnavailable
		}
	}
	if shutdownErr != nil || drainErr != nil || closeErr != nil {
		return errRuntimeUnavailable
	}
	if ctx.Err() != nil && (first.err == nil || errors.Is(first.err, http.ErrServerClosed)) {
		return nil
	}
	return errRuntimeUnavailable
}
