package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zasp-ai/zasp-sec/services/gatewaypodidentity"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	flags := flag.NewFlagSet("gateway-reviewer-publisher", flag.ContinueOnError)
	// Do not echo rejected arguments: credentials are never accepted as flags.
	flags.SetOutput(io.Discard)
	var config gatewaypodidentity.PublisherConfig
	flags.StringVar(&config.SourceDirectory, "source-directory", "", "operator-mounted projected volume")
	flags.StringVar(&config.SourceName, "source-name", "", "projected reviewer token filename")
	flags.StringVar(&config.DestinationDirectory, "destination-directory", "", "preprovisioned private 0700 directory")
	flags.DurationVar(&config.PollInterval, "poll-interval", time.Second, "rotation polling interval")
	flags.DurationVar(&config.MinimumRemainingLifetime, "minimum-remaining-lifetime", 30*time.Second, "minimum local token lifetime")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stdout, "gateway-reviewer-publisher -source-directory PATH -source-name NAME -destination-directory PATH [-poll-interval 1s] [-minimum-remaining-lifetime 30s]")
			return 0
		}
		fmt.Fprintln(os.Stderr, "reviewer publisher configuration rejected")
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "reviewer publisher configuration rejected")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := gatewaypodidentity.RunReviewerPublisher(ctx, config); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "reviewer publisher unavailable")
		return 1
	}
	return 0
}
