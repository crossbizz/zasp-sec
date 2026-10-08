package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Tracing must retain the selected adapter's callback capability. An absent
// capability is legacy only when the underlying database is not selected.
func (d *tracedJSONDatabase) ConnectorOAuthCallbackAuthorityRequired() bool {
	if d == nil || invalidRuntimeValue(d.next) {
		return false
	}
	required, ok := d.next.(interface{ ConnectorOAuthCallbackAuthorityRequired() bool })
	return ok && required.ConnectorOAuthCallbackAuthorityRequired()
}
func (d *tracedJSONDatabase) PrepareConnectorOAuthCallback(ctx context.Context, phase string, consumed apiserver.OAuthConsumption) error {
	if d == nil || invalidRuntimeValue(d.next) || ctx == nil || ctx.Err() != nil {
		return apiserver.ErrRepositoryUnavailable
	}
	switch phase {
	case "secret", "provider", "cleanup":
	default:
		return apiserver.ErrAuthorizationDenied
	}
	capability, ok := d.next.(interface {
		PrepareConnectorOAuthCallback(context.Context, string, apiserver.OAuthConsumption) error
	})
	if ok {
		return capability.PrepareConnectorOAuthCallback(ctx, phase, consumed)
	}
	if d.ConnectorOAuthCallbackAuthorityRequired() {
		return apiserver.ErrRepositoryUnavailable
	}
	return nil
}
