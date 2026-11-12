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
	"github.com/zasp-ai/zasp-sec/services/platform/localcloud"
)

const healthListenAddress = ":8081"

var (
	buildVersion           = "dev"
	errInvalidBuildVersion = errors.New("invalid build version")
	errOutputUnavailable   = errors.New("output unavailable")
	errRuntimeUnavailable  = errors.New("runtime unavailable")
)

func main() {
	if handled, err := runConfigurationCommand(os.Args[1:], os.LookupEnv, os.Stdout); handled {
		if err != nil {
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if localcloud.Require() != nil {
		reportStartupRefusal(os.Stderr, "local-cloud")
		os.Exit(1)
	}
	config, err := loadRuntimeConfigFromEnvironment(os.LookupEnv)
	if err != nil {
		reportStartupRefusal(os.Stderr, "configuration")
		os.Exit(1)
	}
	dependencies, err := buildRuntimeDependenciesStaged(ctx, config)
	if err != nil {
		reportStartupRefusal(os.Stderr, startupDependencyStage(err))
		os.Exit(1)
	}
	if err := serveRuntime(ctx, os.Stdout, buildVersion, config, dependencies, net.Listen); err != nil {
		reportStartupRefusal(os.Stderr, "serve")
		os.Exit(1)
	}
}

// startupDependencyStage names the dependency construction stage that refused
// startup. The value always comes from the closed roster in
// runtimeDependencyFailurePhase, so it never carries configuration values,
// credentials or provider error text.
func startupDependencyStage(err error) string {
	return "dependency:" + runtimeDependencyFailurePhase(err)
}

// reportStartupRefusal tells the operator which fixed stage refused startup.
// Without it a refused process exits with status 1 and no output, which makes
// a wrong database collation, an unreachable dependency and a missing
// registration indistinguishable.
func reportStartupRefusal(output io.Writer, stage string) {
	if output == nil {
		return
	}
	_, _ = io.WriteString(output, "agentsec-api startup refused: stage="+stage+"\n")
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
	server, err := healthserver.New(healthserver.Config{Service: "agentsec-api", Version: version})
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
	_, err := io.WriteString(output, "agentsec-api build "+version+"\n")
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
