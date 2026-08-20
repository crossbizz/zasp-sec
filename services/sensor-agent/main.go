package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zasp-ai/zasp-sec/services/health"
)

const sensorHealthAddress = ":8081"

var buildVersion = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config, err := loadSensorAgentConfig(os.Getenv)
	if err != nil {
		os.Exit(1)
	}
	dependencies, err := buildProductionSensorAgentDependencies(config)
	if err != nil {
		os.Exit(1)
	}
	if serveSensorAgent(ctx, os.Stdout, buildVersion, config, dependencies, net.Listen) != nil {
		os.Exit(1)
	}
}

func serveSensorAgent(ctx context.Context, output io.Writer, version string, config sensorAgentConfig, dependencies sensorAgentDependencies, listen func(string, string) (net.Listener, error)) (resultErr error) {
	if ctx == nil || output == nil || !validBuildVersion(version) || !validSensorAgentConfig(config) || dependencies.Processor == nil || nilAgentValue(dependencies.Runtime) || dependencies.token == nil || listen == nil {
		return errSensorRuntime
	}
	defer func() {
		if recover() != nil {
			resultErr = errSensorRuntime
		}
		if err := dependencies.Close(); err != nil && resultErr == nil {
			resultErr = errSensorRuntime
		}
	}()
	handler, err := health.New(health.Config{Service: "sensor-agent", Version: version})
	if err != nil {
		return errSensorRuntime
	}
	listener, err := listen("tcp", sensorHealthAddress)
	if err != nil || listener == nil {
		if listener != nil {
			_ = listener.Close()
		}
		return errSensorRuntime
	}
	if _, err := fmt.Fprintf(output, "sensor-agent build %s\n", version); err != nil {
		_ = listener.Close()
		return errSensorRuntime
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	ticker := time.NewTicker(config.PollInterval)
	defer ticker.Stop()
	loopDone := make(chan error, 1)
	go func() { loopDone <- runSensorAgentLoop(runtimeCtx, dependencies.Runtime, ticker.C, handler.SetReady) }()
	var first error
	serverFinished, loopFinished := false, false
	select {
	case <-ctx.Done():
	case first = <-serverDone:
		serverFinished = true
	case first = <-loopDone:
		loopFinished = true
	}
	handler.SetReady(false)
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	shutdownErr := server.Shutdown(shutdownCtx)
	shutdownCancel()
	closeErr := server.Close()
	_ = listener.Close()
	deadline := time.NewTimer(config.ShutdownTimeout)
	defer deadline.Stop()
	for !serverFinished || !loopFinished {
		select {
		case err := <-serverDone:
			if first == nil {
				first = err
			}
			serverFinished = true
		case err := <-loopDone:
			if first == nil {
				first = err
			}
			loopFinished = true
		case <-deadline.C:
			return errSensorRuntime
		}
	}
	if shutdownErr != nil || closeErr != nil {
		return errSensorRuntime
	}
	if ctx.Err() != nil && (first == nil || errors.Is(first, http.ErrServerClosed)) {
		return nil
	}
	return errSensorRuntime
}

func validBuildVersion(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		if index == 0 || character != '.' && character != '_' && character != '+' && character != '-' {
			return false
		}
	}
	return true
}
