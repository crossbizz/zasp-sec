package identity

import (
	"context"
	"strings"
	"time"
)

type SessionAuthenticator struct {
	adapter *Adapter
}

func NewSessionAuthenticator(adapter *Adapter) (*SessionAuthenticator, error) {
	if adapter == nil || nilInterface(adapter.driver) {
		return nil, ErrConfiguration
	}
	return &SessionAuthenticator{adapter: adapter}, nil
}

func (authenticator *SessionAuthenticator) Authenticate(ctx context.Context, authorization string) (ExternalPrincipal, error) {
	if authenticator == nil || authenticator.adapter == nil || !validContext(ctx) ||
		!strings.HasPrefix(authorization, "Bearer ") || strings.Count(authorization, " ") != 1 {
		return ExternalPrincipal{}, ErrAuthentication
	}
	principal, err := authenticator.adapter.Authenticate(ctx, strings.TrimPrefix(authorization, "Bearer "))
	if err != nil {
		return ExternalPrincipal{}, ErrAuthentication
	}
	return principal, nil
}

type FreshAuthGuard struct {
	adapter    *Adapter
	maximumAge time.Duration
}

func NewFreshAuthGuard(adapter *Adapter, maximumAge time.Duration) (*FreshAuthGuard, error) {
	if adapter == nil || nilInterface(adapter.driver) || maximumAge <= 0 || maximumAge > 15*time.Minute {
		return nil, ErrConfiguration
	}
	return &FreshAuthGuard{adapter: adapter, maximumAge: maximumAge}, nil
}

func (guard *FreshAuthGuard) Run(
	ctx context.Context,
	principal ExternalPrincipal,
	operation func(context.Context, ExternalPrincipal) error,
) (resultErr error) {
	if guard == nil || guard.adapter == nil || !validContext(ctx) || !principal.valid() || operation == nil {
		return ErrFreshAuthentication
	}
	fresh, err := guard.adapter.Revalidate(ctx, principal)
	if err != nil {
		return ErrFreshAuthentication
	}
	now := guard.adapter.now()
	if fresh.authenticatedAt.Before(now.Add(-guard.maximumAge)) || fresh.authenticatedAt.After(now) || !fresh.expiresAt.After(now) {
		return ErrFreshAuthentication
	}
	defer func() {
		if recover() != nil {
			resultErr = ErrFreshAuthentication
		}
	}()
	if err := operation(ctx, fresh); err != nil || ctx.Err() != nil {
		return ErrFreshAuthentication
	}
	return nil
}
