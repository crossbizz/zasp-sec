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
	if os.Getenv("ZASP_SENSOR_ROLE") == "lineage-layout" {
		uid, err := parseBoundedInteger(os.Getenv("ZASP_LINEAGE_CONSUMER_UID"), 1, 2147483647)
		if err != nil || os.Getenv("ZASP_SENSOR_TOKEN_FILE") != "" || initializeLineageLayout(os.Getenv("ZASP_LINEAGE_LAYOUT_DIRECTORY"), uint32(uid)) != nil {
			os.Exit(1)
		}
		return
	}
	if role := os.Getenv("ZASP_SENSOR_ROLE"); role == "lineage-producer" {
		config, err := loadLineageProducerDaemonConfig(os.Getenv)
		if err != nil {
			os.Exit(1)
		}
		dependencies, err := buildProductionLineageProducer(config)
		if err != nil {
			os.Exit(1)
		}
		if serveSensorDaemon(ctx, os.Stdout, buildVersion, "sensor-lineage-producer", ":8082", config.PollInterval, config.ShutdownTimeout, dependencies.run, dependencies.Close, net.Listen) != nil {
			os.Exit(1)
		}
		return
	} else if role != "" && role != "legacy-consumer" && role != "lineage-consumer" {
		os.Exit(1)
	}
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
	if ctx == nil || output == nil || !validBuildVersion(version) || !validSensorAgentConfig(config) || (dependencies.Processor == nil) == (dependencies.Lineage == nil) || nilAgentValue(dependencies.Runtime) || dependencies.token == nil || listen == nil {
		return errSensorRuntime
	}
	return serveSensorDaemon(ctx, output, version, "sensor-agent", sensorHealthAddress, config.PollInterval, config.ShutdownTimeout, func(ctx context.Context, ticks <-chan time.Time, ready func(bool)) error {
		return runSensorAgentLoop(ctx, dependencies.Runtime, ticks, ready)
	}, dependencies.Close, listen)
}

func serveSensorDaemon(ctx context.Context, output io.Writer, version, service, address string, interval, shutdown time.Duration, run func(context.Context, <-chan time.Time, func(bool)) error, closeDependencies func() error, listen func(string, string) (net.Listener, error)) (resultErr error) {
	if ctx == nil || output == nil || !validBuildVersion(version) || run == nil || closeDependencies == nil || listen == nil || interval < 50*time.Millisecond || interval > 30*time.Second || shutdown < 5*time.Second || shutdown > time.Minute {
		return errSensorRuntime
	}
	defer func() {
		if recover() != nil {
			resultErr = errSensorRuntime
		}
		if err := closeDependencies(); err != nil && resultErr == nil {
			resultErr = errSensorRuntime
		}
	}()
	handler, err := health.New(health.Config{Service: service, Version: version})
	if err != nil {
		return errSensorRuntime
	}
	listener, err := listen("tcp", address)
	if err != nil || listener == nil {
		if listener != nil {
			_ = listener.Close()
		}
		return errSensorRuntime
	}
	if _, err := fmt.Fprintf(output, "%s build %s\n", service, version); err != nil {
		_ = listener.Close()
		return errSensorRuntime
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	loopDone := make(chan error, 1)
	go func() { loopDone <- run(runtimeCtx, ticker.C, handler.SetReady) }()
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
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdown)
	shutdownErr := server.Shutdown(shutdownCtx)
	shutdownCancel()
	closeErr := server.Close()
	_ = listener.Close()
	deadline := time.NewTimer(shutdown)
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
