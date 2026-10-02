package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func (d *tracedJSONDatabase) RiskAutomaticSourcesAvailable(ctx context.Context) (bool, error) {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return false, apiserver.ErrRepositoryUnavailable
	}
	probe, ok := d.next.(interface {
		RiskAutomaticSourcesAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return probe.RiskAutomaticSourcesAvailable(ctx)
}
