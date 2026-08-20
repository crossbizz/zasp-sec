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

const (
	productionControlListenAddress = ":8080"
	healthListenAddress            = ":8081"
)

func serveProductionControl(ctx context.Context, output io.Writer, version string, config productionControlConfig, dependencies productionControlDependencies, listen func(string, string) (net.Listener, error)) (resultErr error) {
	if invalidProductionValue(ctx) || invalidProductionValue(output) || !validBuildVersion(version) || !validProductionControlConfig(config) || invalidProductionValue(dependencies.Handler) || dependencies.Ready == nil || dependencies.Close == nil || listen == nil {
		return errControlUnavailable
	}
	defer func() {
		if recover() != nil {
			resultErr = errControlUnavailable
		}
		if err := dependencies.Close(); err != nil && resultErr == nil {
			resultErr = errControlUnavailable
		}
	}()
	if ctx.Err() != nil {
		return nil
	}
	controlListener, err := listen("tcp", productionControlListenAddress)
	if err != nil || invalidProductionValue(controlListener) {
		if !invalidProductionValue(controlListener) {
			_ = controlListener.Close()
		}
		return errControlUnavailable
	}
	healthListener, err := listen("tcp", healthListenAddress)
	if err != nil || invalidProductionValue(healthListener) {
		_ = controlListener.Close()
		if !invalidProductionValue(healthListener) {
			_ = healthListener.Close()
		}
		return errControlUnavailable
	}
	if err := writeBuildVersion(output, version); err != nil {
		_ = controlListener.Close()
		_ = healthListener.Close()
		return err
	}
	health, err := healthserver.New(healthserver.Config{
		Service: "gateway-control", Version: version, ReadyInterval: time.Second, ReadyMaxInterval: 30 * time.Second,
		ReadyCheck: func(readyCtx context.Context) bool { return dependencies.Ready(readyCtx) == nil },
	})
	if err != nil {
		_ = controlListener.Close()
		_ = healthListener.Close()
		return errControlUnavailable
	}
	control := &http.Server{Handler: dependencies.Handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: config.OperationTimeout, WriteTimeout: config.OperationTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type serveResult struct {
		name string
		err  error
	}
	results := make(chan serveResult, 2)
	go func() { results <- serveResult{name: "control", err: control.Serve(controlListener)} }()
	go func() { results <- serveResult{name: "health", err: health.Serve(runtimeCtx, healthListener)} }()
	first := serveResult{}
	select {
	case <-ctx.Done():
	case first = <-results:
		cancel()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	shutdownErr := control.Shutdown(shutdownCtx)
	shutdownCancel()
	closeErr := control.Close()
	_ = controlListener.Close()
	_ = healthListener.Close()
	seen := 0
	if first.name != "" {
		seen = 1
	}
	deadline := time.NewTimer(config.ShutdownTimeout)
	defer deadline.Stop()
	for seen < 2 {
		select {
		case value := <-results:
			seen++
			if first.name == "" {
				first = value
			}
		case <-deadline.C:
			return errControlUnavailable
		}
	}
	if shutdownErr != nil || closeErr != nil {
		return errControlUnavailable
	}
	if ctx.Err() != nil && (first.err == nil || errors.Is(first.err, http.ErrServerClosed)) {
		return nil
	}
	return errControlUnavailable
}
