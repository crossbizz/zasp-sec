package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var buildVersion = "dev"

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
