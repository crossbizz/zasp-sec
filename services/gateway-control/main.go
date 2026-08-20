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
)

var (
	buildVersion          = "dev"
	errControlUnavailable = errors.New("gateway control unavailable")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config, err := loadProductionControlConfig(os.Getenv)
	if err != nil {
		os.Exit(1)
	}
	dependencies, err := buildProductionControlDependencies(ctx, config)
	if err != nil {
		os.Exit(1)
	}
	if err := serveProductionControl(ctx, os.Stdout, buildVersion, config, dependencies, net.Listen); err != nil {
		os.Exit(1)
	}
}

func writeBuildVersion(output io.Writer, version string) error {
	if invalidProductionValue(output) || !validBuildVersion(version) {
		return errControlUnavailable
	}
	_, err := io.WriteString(output, "gateway-control build "+version+"\n")
	return err
}

func validBuildVersion(version string) bool {
	if len(version) == 0 || len(version) > 64 {
		return false
	}
	for index := 0; index < len(version); index++ {
		value := version[index]
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' {
			continue
		}
		if index == 0 || value != '.' && value != '_' && value != '+' && value != '-' {
			return false
		}
	}
	return true
}

func invalidProductionValue(value any) bool {
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
