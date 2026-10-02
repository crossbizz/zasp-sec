package main

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func (database *tracedJSONDatabase) TemporalDiscoveryAvailable(ctx context.Context, authority string) (bool, error) {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil || ctx.Err() != nil {
		return false, apiserver.ErrRepositoryUnavailable
	}
	capability, ok := database.next.(interface {
		TemporalDiscoveryAvailable(context.Context, string) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return capability.TemporalDiscoveryAvailable(ctx, authority)
}
