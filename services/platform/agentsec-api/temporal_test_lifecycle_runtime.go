package main

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Preserve the optional74 lifecycle capabilities across the tracing boundary.
// Only an absent capability or an explicit unhandled result permits fallback.
func (d *tracedJSONDatabase) CancelTemporalTestRun(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return nil, false, apiserver.ErrRepositoryUnavailable
	}
	if c, ok := d.next.(interface {
		CancelTemporalTestRun(context.Context, ...any) (json.RawMessage, bool, error)
	}); ok {
		return c.CancelTemporalTestRun(ctx, args...)
	}
	return nil, false, nil
}
func (d *tracedJSONDatabase) ReadTemporalTestApproval(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return nil, false, apiserver.ErrRepositoryUnavailable
	}
	if c, ok := d.next.(interface {
		ReadTemporalTestApproval(context.Context, ...any) (json.RawMessage, bool, error)
	}); ok {
		return c.ReadTemporalTestApproval(ctx, args...)
	}
	return nil, false, nil
}
func (d *tracedJSONDatabase) DecideTemporalTestApproval(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return nil, false, apiserver.ErrRepositoryUnavailable
	}
	if c, ok := d.next.(interface {
		DecideTemporalTestApproval(context.Context, ...any) (json.RawMessage, bool, error)
	}); ok {
		return c.DecideTemporalTestApproval(ctx, args...)
	}
	return nil, false, nil
}
func (d *tracedJSONDatabase) PageTemporalTestApprovals(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return nil, false, apiserver.ErrRepositoryUnavailable
	}
	if c, ok := d.next.(interface {
		PageTemporalTestApprovals(context.Context, ...any) (json.RawMessage, bool, error)
	}); ok {
		return c.PageTemporalTestApprovals(ctx, args...)
	}
	return nil, false, nil
}
