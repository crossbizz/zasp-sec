package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/skillfixture"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) > 1 {
		if os.Args[1] == "--run-synthetic-skill" || os.Args[1] == "--run-synthetic-skill-mounted" {
			// Bound the whole process, including a stalled handoff on stdin.
			timeout := time.AfterFunc(skillfixture.MaxDuration, func() { os.Exit(2) })
			defer timeout.Stop()
		}
		if fixtureCommand(ctx, os.Args[1:], os.Stdin, os.Stdout) != nil {
			os.Exit(1)
		}
		return
	}
	config, err := loadRuntimeConfig(os.Getenv)
	_ = os.Unsetenv("ZASP_ATTACK_LAB_EGRESS_TOKEN")
	if err != nil || runProduction(ctx, config) != nil {
		os.Exit(1)
	}
}
