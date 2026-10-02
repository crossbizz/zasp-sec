package main

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// The decorator must preserve74's positive family selection and its errors.
// Only an absent capability or explicit unhandled result permits legacy routing.
func (d *tracedJSONDatabase) MutateTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return nil, false, apiserver.ErrRepositoryUnavailable
	}
	if c, ok := d.next.(interface {
		MutateTemporalTestDefinition(context.Context, ...any) (json.RawMessage, bool, error)
	}); ok {
		return c.MutateTemporalTestDefinition(ctx, args...)
	}
	return nil, false, nil
}
func (d *tracedJSONDatabase) ReadTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return nil, false, apiserver.ErrRepositoryUnavailable
	}
	if c, ok := d.next.(interface {
		ReadTemporalTestDefinition(context.Context, ...any) (json.RawMessage, bool, error)
	}); ok {
		return c.ReadTemporalTestDefinition(ctx, args...)
	}
	return nil, false, nil
}
func (d *tracedJSONDatabase) ActivateTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return nil, false, apiserver.ErrRepositoryUnavailable
	}
	if c, ok := d.next.(interface {
		ActivateTemporalTestDefinition(context.Context, ...any) (json.RawMessage, bool, error)
	}); ok {
		return c.ActivateTemporalTestDefinition(ctx, args...)
	}
	return nil, false, nil
}
func (d *tracedJSONDatabase) ReplayTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return nil, false, apiserver.ErrRepositoryUnavailable
	}
	if c, ok := d.next.(interface {
		ReplayTemporalTestDefinition(context.Context, ...any) (json.RawMessage, bool, error)
	}); ok {
		return c.ReplayTemporalTestDefinition(ctx, args...)
	}
	return nil, false, nil
}
