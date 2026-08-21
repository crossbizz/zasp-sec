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

const productionIngestListenAddress = ":8080"

func serveProductionIngest(ctx context.Context, output io.Writer, version string, config productionIngestConfig, dependencies productionIngestDependencies, listen func(string, string) (net.Listener, error)) (resultErr error) {
	if invalidRuntimeValue(ctx) || invalidRuntimeValue(output) || !validBuildVersion(version) || !validProductionIngestConfig(config) || invalidRuntimeValue(dependencies.Handler) || dependencies.Ready == nil || dependencies.Reconcile == nil || dependencies.ReconcileInterval != config.ReconciliationInterval || dependencies.Close == nil || listen == nil {
		return errRuntimeUnavailable
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			resultErr = errRuntimeUnavailable
		}
		if closeErr := dependencies.Close(); closeErr != nil && resultErr == nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	if ctx.Err() != nil {
		return nil
	}
	privateListener, err := listen("tcp", productionIngestListenAddress)
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
		Service: "event-ingest", Version: version, ReadyInterval: time.Second, ReadyMaxInterval: 30 * time.Second,
		ReadyCheck: func(readyCtx context.Context) bool { return dependencies.Ready(readyCtx) == nil },
	})
	if err != nil {
		_ = privateListener.Close()
		_ = healthListener.Close()
		return errRuntimeUnavailable
	}
	private := &http.Server{
		Handler: dependencies.Handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: config.OperationTimeout,
		WriteTimeout: config.OperationTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	reconciliationCtx, cancelReconciliation := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelReconciliation()
	stopReconciliation := make(chan struct{})
	type serveResult struct {
		name string
		err  error
	}
	results := make(chan serveResult, 3)
	go func() { results <- serveResult{name: "private", err: private.Serve(privateListener)} }()
	go func() { results <- serveResult{name: "health", err: health.Serve(runtimeCtx, healthListener)} }()
	go func() {
		results <- serveResult{name: "reconciliation", err: runProductionReconciliationLoop(reconciliationCtx, stopReconciliation, dependencies.ReconcileInterval, dependencies.Reconcile)}
	}()

	first := serveResult{}
	select {
	case <-ctx.Done():
	case first = <-results:
		cancel()
	}
	close(stopReconciliation)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	shutdownErr := private.Shutdown(shutdownCtx)
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
			cancelReconciliation()
			return errRuntimeUnavailable
		}
	}
	if shutdownErr != nil || closeErr != nil {
		return errRuntimeUnavailable
	}
	if ctx.Err() != nil && (first.err == nil || errors.Is(first.err, http.ErrServerClosed)) {
		return nil
	}
	return errRuntimeUnavailable
}

func runProductionReconciliationLoop(ctx context.Context, stop <-chan struct{}, interval time.Duration, reconcile func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || stop == nil || interval < time.Millisecond || reconcile == nil {
		return errRuntimeUnavailable
	}
	for {
		select {
		case <-stop:
			return nil
		case <-ctx.Done():
			return nil
		default:
		}
		if err := reconcile(ctx); err != nil {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-stop:
			timer.Stop()
			return nil
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
