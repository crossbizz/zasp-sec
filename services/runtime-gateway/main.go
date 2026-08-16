package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
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
	if err := serveProcess(ctx, os.Stdout, buildVersion, net.Listen); err != nil {
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
			_ = callHealthClose(candidate)
		}
		result = errRuntimeUnavailable
	}()

	if !validBuildVersion(version) {
		return errInvalidBuildVersion
	}
	if invalidRuntimeValue(ctx) || invalidRuntimeValue(output) || listen == nil {
		return errRuntimeUnavailable
	}
	server, err := newHealthServer(healthServerConfig{service: "runtime-gateway", version: version})
	if err != nil {
		return errRuntimeUnavailable
	}
	if ctx.Err() != nil {
		return nil
	}
	listener, err := listen("tcp", healthListenAddress)
	if err != nil {
		if !invalidRuntimeValue(listener) {
			if closeErr := callHealthClose(listener); closeErr != nil {
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
		closeErr := callHealthClose(listener)
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
	_, err := io.WriteString(output, "runtime-gateway build "+version+"\n")
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
