package main

import (
	"context"
)

func startPreciseLineageGeneration(ctx context.Context, nodeName, binding string, api lineageIdentityAPI, boot *hostBootReader, endpoint *lineageSocket, spool lineageGenerationPublisher) (*lineageGeneration, error) {
	return startLineageGenerationProfile(ctx, nodeName, binding, api, boot, endpoint, spool, "tetragon-local-stream-v3")
}
