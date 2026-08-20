package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
)

const healthListenAddress = ":8081"

var (
	buildVersion           = "dev"
	errInvalidBuildVersion = errors.New("invalid build version")
	errOutputUnavailable   = errors.New("output unavailable")
	errRuntimeUnavailable  = errors.New("runtime unavailable")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mode := workerMode(os.Getenv("ZASP_WORKER_MODE"))
	if mode == workerModeProjectionSearchInit || mode == workerModeProjectionGraphInit {
		config, err := loadProjectionInitConfig(os.Getenv)
		if err != nil || runProductionProjectionInit(ctx, config) != nil {
			os.Exit(1)
		}
		return
	}
	config, err := loadWorkerRuntimeConfig(os.Getenv)
	if err != nil {
		os.Exit(1)
	}
	dependencies, err := buildWorkerRuntime(ctx, config)
	if err != nil {
		os.Exit(1)
	}
	if err := serveWorkerRuntime(ctx, os.Stdout, buildVersion, config, dependencies, net.Listen); err != nil {
		os.Exit(1)
	}
}

func serveProcess(ctx context.Context, output io.Writer, version string, listen func(string, string) (net.Listener, error)) (result error) {
	var candidate net.Listener
	defer func() {
		if recover() == nil {
			return
		}
		if !invalidRuntimeValue(candidate) {
			_ = candidate.Close()
		}
		result = errRuntimeUnavailable
	}()

	if !validBuildVersion(version) {
		return errInvalidBuildVersion
	}
	if invalidRuntimeValue(ctx) || invalidRuntimeValue(output) || listen == nil {
		return errRuntimeUnavailable
	}
	server, err := healthserver.New(healthserver.Config{Service: "agentsec-worker", Version: version})
	if err != nil {
		return errRuntimeUnavailable
	}
	if ctx.Err() != nil {
		return nil
	}
	listener, err := listen("tcp", healthListenAddress)
	if err != nil {
		if !invalidRuntimeValue(listener) {
			if closeErr := listener.Close(); closeErr != nil {
				return errRuntimeUnavailable
			}
		}
		return err
	}
	if invalidRuntimeValue(listener) {
		return errRuntimeUnavailable
	}
	candidate = listener
	if err := run(output, version); err != nil {
		closeErr := listener.Close()
		candidate = nil
		if closeErr != nil {
			return errRuntimeUnavailable
		}
		return err
	}
	result = server.Serve(ctx, listener)
	candidate = nil
	return result
}

func run(output io.Writer, version string) error {
	if !validBuildVersion(version) {
		return errInvalidBuildVersion
	}
	if output == nil {
		return errOutputUnavailable
	}
	_, err := io.WriteString(output, "agentsec-worker build "+version+"\n")
	return err
}

func validBuildVersion(version string) bool {
	if len(version) == 0 || len(version) > 64 {
		return false
	}
	for index := 0; index < len(version); index++ {
		character := version[index]
		alphanumeric := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if alphanumeric {
			continue
		}
		if index == 0 || character != '.' && character != '_' && character != '+' && character != '-' {
			return false
		}
	}
	return true
}

func invalidRuntimeValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
