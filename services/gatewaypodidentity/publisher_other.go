//go:build !linux

package gatewaypodidentity

import "context"

func runReviewerPublisher(context.Context, PublisherConfig) error { return ErrDenied }
