package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var (
	buildVersion          = "dev"
	errRuntimeUnavailable = errors.New("red team adapter unavailable")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config, err := loadRuntimeConfig(os.Getenv)
	if err != nil {
		os.Exit(1)
	}
	dependencies, err := buildProductionDependencies(ctx, config)
	if err != nil {
		os.Exit(1)
	}
	if err := serveProduction(ctx, buildVersion, config, dependencies, net.Listen); err != nil {
		os.Exit(1)
	}
}
