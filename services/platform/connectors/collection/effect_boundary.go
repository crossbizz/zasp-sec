package collection

import (
	"context"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type effectContextKey struct{}
type effectContext struct {
	id    string
	check func(context.Context) error
	scope domain.Scope
}

// WithScopedProductEffect binds in-memory artifact reads to the same exact
// tenant/effect authority as outbound IO. It never caches the guard's verdict.
func WithScopedProductEffect(ctx context.Context, id string, scope domain.Scope, deadline time.Time, check func(context.Context) error) (context.Context, context.CancelFunc, error) {
	if scope.Validate() != nil {
		return nil, nil, ErrContract
	}
	bounded, cancel, err := WithProductEffect(ctx, id, deadline, check)
	if err != nil {
		return nil, nil, err
	}
	return context.WithValue(bounded, effectContextKey{}, effectContext{id: id, check: check, scope: scope}), cancel, nil
}

func RequireScopedProductEffect(ctx context.Context, id string, scope domain.Scope) error {
	if ctx == nil || scope.Validate() != nil || !ValidExecutionIdentity(0, id) {
		return ErrContract
	}
	binding, ok := ctx.Value(effectContextKey{}).(effectContext)
	if !ok || binding.id != id || binding.scope != scope || binding.check == nil {
		return ErrContract
	}
	return CheckEffectBoundary(ctx)
}

// WithProductEffect carries a product SQL guard only inside the Activity. It
// is not serialized. Each outbound boundary checks again; this is not an atomic
// fence around external IO and cannot turn a lost response into a safe retry.
func WithProductEffect(ctx context.Context, id string, deadline time.Time, check func(context.Context) error) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil || !ValidExecutionIdentity(0, id) || deadline.IsZero() || !deadline.After(time.Now()) || check == nil {
		return nil, nil, ErrContract
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	return context.WithValue(bounded, effectContextKey{}, effectContext{id: id, check: check}), cancel, nil
}

func RequireProductEffect(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	if ctx == nil {
		return ErrContract
	}
	binding, ok := ctx.Value(effectContextKey{}).(effectContext)
	if !ok || binding.id != id || binding.check == nil {
		return ErrContract
	}
	return CheckEffectBoundary(ctx)
}

func CheckEffectBoundary(ctx context.Context) error {
	if ctx == nil {
		return ErrContract
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if binding, ok := ctx.Value(effectContextKey{}).(effectContext); ok {
		if binding.check == nil {
			return ErrContract
		}
		if err := binding.check(ctx); err != nil {
			failure, _ := NewFailure(FailureRevoked, time.Time{})
			return failure
		}
		return ctx.Err()
	}
	return nil
}

// EffectTransport also covers SDK-internal sends and retries. Retained legacy
// callers without a product effect context preserve their existing behavior.
type EffectTransport struct{ Next http.RoundTripper }

func (t EffectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || t.Next == nil {
		if r != nil && r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, ErrContract
	}
	if err := CheckEffectBoundary(r.Context()); err != nil {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, err
	}
	return t.Next.RoundTrip(r)
}
