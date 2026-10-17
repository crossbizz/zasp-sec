package gatewaypodidentity

import (
	"context"
	"time"
)

// PublisherConfig selects an operator-owned Kubernetes projected volume and a
// preprovisioned current-user-owned 0700 output directory. Tokens are never
// configuration values. The fixed output filename is credential.
type PublisherConfig struct {
	SourceDirectory          string
	SourceName               string
	DestinationDirectory     string
	PollInterval             time.Duration
	MinimumRemainingLifetime time.Duration
}

// RunReviewerPublisher blocks until cancellation or a safety/IO failure. The
// caller owns its goroutine and must join it. Cancellation withdraws only the
// exact owned output before returning. Local expiry is advisory, not provider
// authentication. No duration bound is promised for blocked kernel filesystem IO.
func RunReviewerPublisher(ctx context.Context, config PublisherConfig) error {
	return runReviewerPublisher(ctx, config)
}
