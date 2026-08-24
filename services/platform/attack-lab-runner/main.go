package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config, err := loadRuntimeConfig(os.Getenv)
	_ = os.Unsetenv("ZASP_ATTACK_LAB_EGRESS_TOKEN")
	if err != nil || runProduction(ctx, config) != nil {
		os.Exit(1)
	}
}
