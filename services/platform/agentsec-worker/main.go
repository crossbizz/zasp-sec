package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"reflect"
	"regexp"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
	"github.com/zasp-ai/zasp-sec/services/platform/localcloud"
)

const healthListenAddress = ":8081"

// localHealthPortVariable moves the health listener to a loopback port, so a
// developer can run several worker modes on one machine. It is read only
// when the local cloud emulator is enabled, which localcloud permits only in
// a development or test environment. Everywhere else the listener is the
// fixed healthListenAddress and this setting has no effect.
const localHealthPortVariable = "ZASP_LOCAL_HEALTH_PORT"

var localHealthPortPattern = regexp.MustCompile(`^[1-9][0-9]{3,4}$`)

func healthListener(local localcloud.Settings, getenv func(string) string, listen func(string, string) (net.Listener, error)) func(string, string) (net.Listener, error) {
	if !local.Enabled() || getenv == nil || listen == nil {
		return listen
	}
	port := getenv(localHealthPortVariable)
	if !localHealthPortPattern.MatchString(port) {
		return listen
	}
	return func(network, address string) (net.Listener, error) {
		if address != healthListenAddress {
			return listen(network, address)
		}
		return listen(network, net.JoinHostPort("127.0.0.1", port))
	}
}

var (
	buildVersion           = "dev"
	errInvalidBuildVersion = errors.New("invalid build version")
	errOutputUnavailable   = errors.New("output unavailable")
	errRuntimeUnavailable  = errors.New("runtime unavailable")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if localcloud.Require() != nil {
		_, _ = io.WriteString(os.Stderr, "agentsec-worker startup refused: stage=local-cloud\n")
		os.Exit(1)
	}
	mode := workerMode(os.Getenv("ZASP_WORKER_MODE"))
	if recoveryJobModeEnabled(mode) {
		if runProductionRecoveryJob(ctx, os.Getenv, "/dev/termination-log") != nil {
			os.Exit(1)
		}
		return
	}
	if mode == workerModeProjectionSearchInit || mode == workerModeProjectionGraphInit {
		config, err := loadProjectionInitConfig(os.Getenv)
		if err != nil {
			_, _ = io.WriteString(os.Stderr, "agentsec-worker startup refused: stage=configuration\n")
			os.Exit(1)
		}
		if runProductionProjectionInit(ctx, config) != nil {
			_, _ = io.WriteString(os.Stderr, "agentsec-worker startup refused: stage=dependencies:"+currentStartupStage()+"\n")
			os.Exit(1)
		}
		return
	}
	// A refused start names its stage from this fixed list. The stage never
	// carries a setting, credential or provider error.
	config, err := loadWorkerRuntimeConfig(os.Getenv)
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "agentsec-worker startup refused: stage=configuration\n")
		os.Exit(1)
	}
	dependencies, err := buildWorkerRuntime(ctx, config)
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "agentsec-worker startup refused: stage=dependencies:"+currentStartupStage()+"\n")
		os.Exit(1)
	}
	if err := serveWorkerRuntime(ctx, os.Stdout, buildVersion, config, dependencies, healthListener(localcloud.Current(), os.Getenv, net.Listen)); err != nil {
		_, _ = io.WriteString(os.Stderr, "agentsec-worker startup refused: stage=serve\n")
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
