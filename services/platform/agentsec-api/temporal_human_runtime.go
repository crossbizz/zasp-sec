package main

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Preserve optional release capabilities through the production decorator.
// Absent capability keeps the existing route; installed authority errors do not.
func (database *tracedJSONDatabase) TemporalHumanTestFamily(ctx context.Context, identity apiserver.RequestIdentity, definition string) (bool, error) {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil || ctx.Err() != nil {
		return false, apiserver.ErrRepositoryUnavailable
	}
	capability, ok := database.next.(interface {
		TemporalHumanTestFamily(context.Context, apiserver.RequestIdentity, string) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return capability.TemporalHumanTestFamily(ctx, identity, definition)
}

func (database *tracedJSONDatabase) RunTemporalHumanTest(ctx context.Context, identity apiserver.RequestIdentity, input apiserver.SecurityAgentRunRequest) (json.RawMessage, bool, error) {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil || ctx.Err() != nil {
		return nil, false, apiserver.ErrRepositoryUnavailable
	}
	capability, ok := database.next.(interface {
		RunTemporalHumanTest(context.Context, apiserver.RequestIdentity, apiserver.SecurityAgentRunRequest) (json.RawMessage, bool, error)
	})
	if !ok {
		return nil, false, nil
	}
	return capability.RunTemporalHumanTest(ctx, identity, input)
}
